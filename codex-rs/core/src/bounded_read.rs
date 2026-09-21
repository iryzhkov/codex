use crate::function_tool::FunctionCallError;
use crate::tools::context::FunctionToolOutput;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolPayload;
use crate::tools::context::boxed_tool_output;
use crate::tools::registry::CoreToolRuntime;
use crate::tools::registry::ToolExecutor;
use base64::Engine;
use codex_tools::JsonSchema;
use codex_tools::ResponsesApiTool;
use codex_tools::ToolName;
use codex_tools::ToolSpec;
use rand::RngCore;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::Instant;

pub(crate) const MAX_PROVIDER_REQUESTS: u8 = 4;
pub(crate) const MAX_PROVIDER_REQUEST_BYTES: usize = 32_000;
pub(crate) const MAX_PROVIDER_REQUEST_BYTES_TOTAL: usize = 128_000;
pub(crate) const MAX_TOOL_RESULT_BYTES: usize = 2_048;
pub(crate) const MAX_TOOL_RESULT_BYTES_TOTAL: usize = 8_192;
pub(crate) const MAX_PAGES: u8 = 4;
pub(crate) const MAX_OUTPUT_TOKENS: u64 = 4_000;
pub(crate) const PROVIDER_FRAMING_RESERVE: u64 = 4_096;
pub(crate) const DEADLINE: Duration = Duration::from_secs(15 * 60);
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ARTIFACTS: usize = 64;
const MAX_ARTIFACT_BYTES_TOTAL: u64 = 32 * 1024 * 1024;
const MAX_PAGE_CONTENT_BYTES: usize = 1_024;

const ENV_MANIFEST: &str = "CODEX_BOUNDED_READ_MANIFEST";
const ENV_MANIFEST_SHA256: &str = "CODEX_BOUNDED_READ_MANIFEST_SHA256";
const ENV_REQUEST_ID: &str = "CODEX_BOUNDED_READ_REQUEST_ID";
const ENV_PROJECT_ID: &str = "CODEX_BOUNDED_READ_PROJECT_ID";
const ENV_REVISION: &str = "CODEX_BOUNDED_READ_REVISION";

#[derive(Debug, thiserror::Error)]
pub(crate) enum BoundedReadError {
    #[error("bounded read context is too large")]
    ContextTooLarge,
    #[error("bounded read budget is exhausted")]
    BudgetExhausted,
    #[error("bounded read custody is invalid: {0}")]
    InvalidCustody(String),
    #[error("bounded read deadline exceeded")]
    DeadlineExceeded,
}

impl BoundedReadError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::ContextTooLarge => "context-too-large",
            Self::BudgetExhausted => "budget-exhausted",
            Self::InvalidCustody(_) => "invalid-custody",
            Self::DeadlineExceeded => "deadline-exceeded",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    request_id: String,
    project_id: String,
    revision: String,
    entries: Vec<ManifestEntry>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEntry {
    artifact_id: String,
    path: String,
    sha256: String,
    size: u64,
    media_type: String,
    #[serde(skip)]
    content: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReadPage {
    pub(crate) artifact_id: String,
    pub(crate) sha256: String,
    pub(crate) content_base64: String,
    pub(crate) byte_start: u64,
    pub(crate) byte_end: u64,
    pub(crate) next_cursor: Option<String>,
    pub(crate) end: bool,
}

#[derive(Default, Debug)]
struct Admission {
    provider_requests: u8,
    provider_bytes: usize,
    pages: u8,
    tool_bytes: usize,
    issued_cursors: BTreeMap<String, Cursor>,
    consumed_cursors: HashSet<String>,
    user_turn_started: bool,
}

#[derive(Clone, Debug)]
struct Cursor {
    artifact_id: String,
    offset: u64,
}

#[derive(Debug)]
pub(crate) struct BoundedReadSession {
    manifest_sha256: String,
    request_id: String,
    project_id: String,
    revision: String,
    entries: BTreeMap<String, ManifestEntry>,
    nonce: [u8; 32],
    started_at: Instant,
    admission: Mutex<Admission>,
}

impl BoundedReadSession {
    pub(crate) fn from_env() -> Result<Option<std::sync::Arc<Self>>, BoundedReadError> {
        let values = [
            env::var_os(ENV_MANIFEST),
            env::var_os(ENV_MANIFEST_SHA256),
            env::var_os(ENV_REQUEST_ID),
            env::var_os(ENV_PROJECT_ID),
            env::var_os(ENV_REVISION),
        ];
        if values.iter().all(Option::is_none) {
            return Ok(None);
        }
        if values.iter().any(Option::is_none) {
            return Err(invalid("bounded read environment is incomplete"));
        }
        let manifest_path = PathBuf::from(values[0].as_ref().expect("checked"));
        let expected_digest = values[1]
            .as_ref()
            .and_then(|value| value.to_str())
            .ok_or_else(|| invalid("manifest digest is not UTF-8"))?;
        let request_id = env_text(&values[2], "request id")?;
        let project_id = env_text(&values[3], "project id")?;
        let revision = env_text(&values[4], "revision")?;
        Self::load(
            &manifest_path,
            expected_digest,
            request_id,
            project_id,
            revision,
            Instant::now(),
        )
        .map(|session| Some(std::sync::Arc::new(session)))
    }

    fn load(
        manifest_path: &Path,
        expected_digest: &str,
        request_id: String,
        project_id: String,
        revision: String,
        started_at: Instant,
    ) -> Result<Self, BoundedReadError> {
        validate_digest(expected_digest)?;
        if !manifest_path.is_absolute() {
            return Err(invalid("manifest path is not absolute"));
        }
        let bytes = read_bounded_absolute(manifest_path, MAX_MANIFEST_BYTES)?;
        if sha256_hex(&bytes) != expected_digest {
            return Err(invalid("manifest digest mismatch"));
        }
        let manifest: Manifest = serde_json::from_slice(&bytes)
            .map_err(|error| invalid(format!("manifest JSON: {error}")))?;
        if manifest.schema != "bounded-read-v1"
            || manifest.request_id != request_id
            || manifest.project_id != project_id
            || manifest.revision != revision
        {
            return Err(invalid("manifest binding mismatch"));
        }
        let root = manifest_path
            .parent()
            .ok_or_else(|| invalid("manifest has no parent"))?;
        if manifest.entries.len() > MAX_ARTIFACTS {
            return Err(invalid("too many artifacts"));
        }
        let mut declared_total = 0_u64;
        let mut paths = HashSet::new();
        let mut ids = HashSet::new();
        for entry in &manifest.entries {
            validate_entry_shape(entry)?;
            declared_total = declared_total
                .checked_add(entry.size)
                .ok_or_else(|| invalid("aggregate artifact size overflow"))?;
            if declared_total > MAX_ARTIFACT_BYTES_TOTAL {
                return Err(invalid("aggregate artifact size exceeds limit"));
            }
            if !paths.insert(entry.path.clone()) || !ids.insert(entry.artifact_id.clone()) {
                return Err(invalid("duplicate artifact id or path"));
            }
        }
        let root_dir = open_directory_absolute(root)?;
        let mut entries = BTreeMap::new();
        for mut entry in manifest.entries {
            entry.content = read_verified_artifact(&root_dir, &entry)?;
            entries.insert(entry.artifact_id.clone(), entry);
        }
        let mut nonce = [0_u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        Ok(Self {
            manifest_sha256: expected_digest.to_owned(),
            request_id,
            project_id,
            revision,
            entries,
            nonce,
            started_at,
            admission: Mutex::new(Admission::default()),
        })
    }

    pub(crate) fn begin_user_turn(&self) -> Result<(), BoundedReadError> {
        self.check_deadline()?;
        let mut state = self
            .admission
            .lock()
            .map_err(|_| invalid("admission lock poisoned"))?;
        if state.user_turn_started {
            return Err(BoundedReadError::BudgetExhausted);
        }
        state.user_turn_started = true;
        Ok(())
    }

    pub(crate) fn remaining(&self) -> Result<Duration, BoundedReadError> {
        DEADLINE
            .checked_sub(self.started_at.elapsed())
            .ok_or(BoundedReadError::DeadlineExceeded)
    }

    pub(crate) fn read_page(
        &self,
        artifact_id: &str,
        cursor: Option<&str>,
    ) -> Result<ReadPage, BoundedReadError> {
        self.check_deadline()?;
        let entry = self
            .entries
            .get(artifact_id)
            .ok_or_else(|| invalid("unknown artifact id"))?;
        let offset = match cursor {
            None => 0,
            Some(token) => {
                let mut state = self
                    .admission
                    .lock()
                    .map_err(|_| invalid("admission lock poisoned"))?;
                if state.consumed_cursors.contains(token) {
                    return Err(invalid("stale cursor"));
                }
                let decoded = state
                    .issued_cursors
                    .remove(token)
                    .ok_or_else(|| invalid("forged cursor"))?;
                if decoded.artifact_id != artifact_id {
                    return Err(invalid("cursor artifact mismatch"));
                }
                state.consumed_cursors.insert(token.to_owned());
                decoded.offset
            }
        };
        if offset > entry.size {
            return Err(invalid("cursor offset exceeds artifact"));
        }
        let remaining = entry.size - offset;
        let amount = usize::try_from(remaining.min(MAX_PAGE_CONTENT_BYTES as u64))
            .map_err(|_| invalid("page size conversion"))?;
        let start = usize::try_from(offset).map_err(|_| invalid("page offset conversion"))?;
        let end = start
            .checked_add(amount)
            .ok_or_else(|| invalid("page range overflow"))?;
        let content = entry
            .content
            .get(start..end)
            .ok_or_else(|| invalid("page range exceeds verified artifact"))?;
        let end_offset = offset
            .checked_add(amount as u64)
            .ok_or(BoundedReadError::BudgetExhausted)?;
        let end = end_offset == entry.size;
        let next_cursor = if end {
            None
        } else {
            let token = self.cursor_token(artifact_id, end_offset);
            let mut state = self
                .admission
                .lock()
                .map_err(|_| invalid("admission lock poisoned"))?;
            state.issued_cursors.insert(
                token.clone(),
                Cursor {
                    artifact_id: artifact_id.to_owned(),
                    offset: end_offset,
                },
            );
            Some(token)
        };
        Ok(ReadPage {
            artifact_id: artifact_id.to_owned(),
            sha256: entry.sha256.clone(),
            content_base64: base64::engine::general_purpose::STANDARD.encode(content),
            byte_start: offset,
            byte_end: end_offset,
            next_cursor,
            end,
        })
    }

    pub(crate) fn admit_tool_result(&self, serialized_len: usize) -> Result<(), BoundedReadError> {
        self.check_deadline()?;
        if serialized_len > MAX_TOOL_RESULT_BYTES {
            return Err(BoundedReadError::BudgetExhausted);
        }
        let mut state = self
            .admission
            .lock()
            .map_err(|_| invalid("admission lock poisoned"))?;
        let pages = state
            .pages
            .checked_add(1)
            .ok_or(BoundedReadError::BudgetExhausted)?;
        let total = state
            .tool_bytes
            .checked_add(serialized_len)
            .ok_or(BoundedReadError::BudgetExhausted)?;
        if pages > MAX_PAGES || total > MAX_TOOL_RESULT_BYTES_TOTAL {
            return Err(BoundedReadError::BudgetExhausted);
        }
        state.pages = pages;
        state.tool_bytes = total;
        Ok(())
    }

    pub(crate) fn validate_provider_request(
        &self,
        encoded: &[u8],
    ) -> Result<(), BoundedReadError> {
        let request: serde_json::Value = serde_json::from_slice(encoded)
            .map_err(|error| invalid(format!("provider request JSON: {error}")))?;
        if request.get("parallel_tool_calls") != Some(&serde_json::Value::Bool(false)) {
            return Err(invalid("bounded request permits no parallel tool calls"));
        }
        let tools = request
            .get("tools")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| invalid("bounded request tools are missing"))?;
        let [tool] = tools.as_slice() else {
            return Err(invalid("bounded request must expose exactly one tool"));
        };
        let parameters = tool
            .get("parameters")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| invalid("bounded read tool parameters are missing"))?;
        let properties = parameters
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| invalid("bounded read tool properties are missing"))?;
        let required = parameters
            .get("required")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| invalid("bounded read tool required fields are missing"))?;
        let exact_tool = tool.get("type").and_then(serde_json::Value::as_str) == Some("function")
            && tool.get("name").and_then(serde_json::Value::as_str)
                == Some("read_custodied_page")
            && tool.get("strict") == Some(&serde_json::Value::Bool(true))
            && parameters.get("type").and_then(serde_json::Value::as_str) == Some("object")
            && parameters.get("additionalProperties") == Some(&serde_json::Value::Bool(false))
            && properties.len() == 2
            && properties.contains_key("artifact_id")
            && properties.contains_key("cursor")
            && required.as_slice() == [serde_json::Value::String("artifact_id".to_string())];
        if !exact_tool {
            return Err(invalid("bounded request tool schema mismatch"));
        }
        Ok(())
    }

    pub(crate) fn admit_provider_request(
        &self,
        serialized_len: usize,
        verified_context_window: u64,
    ) -> Result<(), BoundedReadError> {
        self.check_deadline()?;
        let reserved = u64::try_from(serialized_len)
            .ok()
            .and_then(|value| value.checked_add(MAX_OUTPUT_TOKENS))
            .and_then(|value| value.checked_add(PROVIDER_FRAMING_RESERVE))
            .ok_or(BoundedReadError::ContextTooLarge)?;
        if serialized_len > MAX_PROVIDER_REQUEST_BYTES || reserved > verified_context_window {
            return Err(BoundedReadError::ContextTooLarge);
        }
        let mut state = self
            .admission
            .lock()
            .map_err(|_| invalid("admission lock poisoned"))?;
        let requests = state
            .provider_requests
            .checked_add(1)
            .ok_or(BoundedReadError::BudgetExhausted)?;
        let total = state
            .provider_bytes
            .checked_add(serialized_len)
            .ok_or(BoundedReadError::BudgetExhausted)?;
        if requests > MAX_PROVIDER_REQUESTS || total > MAX_PROVIDER_REQUEST_BYTES_TOTAL {
            return Err(BoundedReadError::BudgetExhausted);
        }
        state.provider_requests = requests;
        state.provider_bytes = total;
        Ok(())
    }

    fn check_deadline(&self) -> Result<(), BoundedReadError> {
        self.remaining().map(|_| ())
    }

    fn cursor_token(&self, artifact_id: &str, offset: u64) -> String {
        let mut hash = Sha256::new();
        hash.update(self.nonce);
        hash.update(self.manifest_sha256.as_bytes());
        hash.update(self.request_id.as_bytes());
        hash.update(self.project_id.as_bytes());
        hash.update(self.revision.as_bytes());
        hash.update(artifact_id.as_bytes());
        hash.update(offset.to_be_bytes());
        hex(&hash.finalize())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadPageArgs {
    artifact_id: String,
    #[serde(default)]
    cursor: Option<String>,
}

pub(crate) struct BoundedReadHandler {
    session: std::sync::Arc<BoundedReadSession>,
}

impl BoundedReadHandler {
    pub(crate) fn new(session: std::sync::Arc<BoundedReadSession>) -> Self {
        Self { session }
    }
}

impl ToolExecutor<ToolInvocation> for BoundedReadHandler {
    fn tool_name(&self) -> ToolName {
        ToolName::plain("read_custodied_page")
    }

    fn spec(&self) -> ToolSpec {
        let properties = BTreeMap::from([
            (
                "artifact_id".to_string(),
                JsonSchema::string(Some(
                    "Custodied artifact identifier from the request package.".to_string(),
                )),
            ),
            (
                "cursor".to_string(),
                JsonSchema::string(Some(
                    "Opaque cursor returned by the preceding page.".to_string(),
                )),
            ),
        ]);
        ToolSpec::Function(ResponsesApiTool {
            name: "read_custodied_page".to_string(),
            description: "Read one bounded page from an allowlisted custodied request artifact."
                .to_string(),
            strict: true,
            defer_loading: None,
            parameters: JsonSchema::object(
                properties,
                Some(vec!["artifact_id".to_string()]),
                Some(false.into()),
            ),
            output_schema: None,
        })
    }

    fn handle<'a>(&'a self, invocation: ToolInvocation) -> codex_tools::ToolExecutorFuture<'a>
    where
        ToolInvocation: 'a,
    {
        Box::pin(async move {
            let ToolPayload::Function { arguments } = invocation.payload else {
                return Err(FunctionCallError::Fatal(
                    "bounded read received a non-function payload".to_string(),
                ));
            };
            let args: ReadPageArgs = serde_json::from_str(&arguments).map_err(|error| {
                FunctionCallError::Fatal(format!(
                    "invalid-custody: invalid bounded read arguments: {error}"
                ))
            })?;
            let page = self
                .session
                .read_page(&args.artifact_id, args.cursor.as_deref())
                .map_err(|error| FunctionCallError::Fatal(format!("{}: {error}", error.code())))?;
            let output = serde_json::to_string(&page).map_err(|error| {
                FunctionCallError::Fatal(format!(
                    "invalid-custody: failed to serialize page: {error}"
                ))
            })?;
            Ok(boxed_tool_output(FunctionToolOutput::from_text(
                output,
                Some(true),
            )))
        })
    }
}

impl CoreToolRuntime for BoundedReadHandler {}

fn env_text(value: &Option<std::ffi::OsString>, name: &str) -> Result<String, BoundedReadError> {
    let text = value
        .as_ref()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(format!("{name} is empty or not UTF-8")))?;
    if text.len() > 256 {
        return Err(invalid(format!("{name} is too long")));
    }
    Ok(text.to_owned())
}

fn validate_entry_shape(entry: &ManifestEntry) -> Result<(), BoundedReadError> {
    if entry.artifact_id.is_empty()
        || entry.artifact_id.len() > 128
        || !entry
            .artifact_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(invalid("invalid artifact id"));
    }
    validate_digest(&entry.sha256)?;
    if entry.size > MAX_ARTIFACT_BYTES || !entry.media_type.starts_with("text/") {
        return Err(invalid("unsupported artifact size or media type"));
    }
    validate_relative_path(&entry.path)
}

fn validate_relative_path(value: &str) -> Result<(), BoundedReadError> {
    if value.is_empty()
        || value.starts_with('/')
        || value.ends_with('/')
        || value.as_bytes().contains(&b'\\')
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(invalid("artifact path is not canonical relative"));
    }
    Ok(())
}

fn read_verified_artifact(root: &File, entry: &ManifestEntry) -> Result<Vec<u8>, BoundedReadError> {
    let file = open_relative(root, Path::new(&entry.path), false)?;
    let metadata = file
        .metadata()
        .map_err(|error| invalid(format!("artifact metadata: {error}")))?;
    if !metadata.is_file() || metadata.len() != entry.size {
        return Err(invalid("artifact is not a declared regular file"));
    }
    let bytes = read_bounded_file(file, entry.size)?;
    if bytes.len() as u64 != entry.size || sha256_hex(&bytes) != entry.sha256 {
        return Err(invalid("artifact size or digest mismatch"));
    }
    Ok(bytes)
}

fn read_bounded_absolute(path: &Path, limit: u64) -> Result<Vec<u8>, BoundedReadError> {
    let root = open_os_root()?;
    let relative = path
        .strip_prefix(Path::new("/"))
        .map_err(|_| invalid("manifest path is not absolute"))?;
    let file = open_relative(&root, relative, false)?;
    let metadata = file
        .metadata()
        .map_err(|error| invalid(format!("bounded file metadata: {error}")))?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(invalid("bounded file is not a regular file within limit"));
    }
    read_bounded_file(file, limit)
}

fn open_directory_absolute(path: &Path) -> Result<File, BoundedReadError> {
    let root = open_os_root()?;
    let relative = path
        .strip_prefix(Path::new("/"))
        .map_err(|_| invalid("directory path is not absolute"))?;
    open_relative(&root, relative, true)
}

fn read_bounded_file(file: File, limit: u64) -> Result<Vec<u8>, BoundedReadError> {
    let capacity = usize::try_from(limit.min(64 * 1024))
        .map_err(|_| invalid("bounded allocation conversion"))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| invalid(format!("bounded read: {error}")))?;
    if bytes.len() as u64 > limit {
        return Err(invalid("bounded file exceeds limit"));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn open_os_root() -> Result<File, BoundedReadError> {
    use std::os::fd::FromRawFd;
    let path = std::ffi::CString::new("/").expect("static root path");
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(invalid(format!(
            "open custody root: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn open_relative(root: &File, path: &Path, directory: bool) -> Result<File, BoundedReadError> {
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    if path.as_os_str().is_empty() {
        return root
            .try_clone()
            .map_err(|error| invalid(format!("clone custody root: {error}")));
    }

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| invalid("custody path contains NUL"))?;
    let mut flags = (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK) as u64;
    if directory {
        flags |= libc::O_DIRECTORY as u64;
    }
    let how = OpenHow {
        flags,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    } as libc::c_int;
    if fd < 0 {
        return Err(invalid(format!(
            "rooted custody open: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(not(target_os = "linux"))]
fn open_os_root() -> Result<File, BoundedReadError> {
    File::open("/").map_err(|error| invalid(format!("open custody root: {error}")))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn open_relative(root: &File, path: &Path, directory: bool) -> Result<File, BoundedReadError> {
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    let mut current = root
        .try_clone()
        .map_err(|error| invalid(format!("clone custody root: {error}")))?;
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(name) = component else {
            return Err(invalid("non-canonical custody path"));
        };
        let name = std::ffi::CString::new(name.as_bytes())
            .map_err(|_| invalid("custody path contains NUL"))?;
        let last = index + 1 == components.len();
        let mut flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
        if !last || directory {
            flags |= libc::O_DIRECTORY;
        }
        let fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(invalid(format!(
                "rooted custody open: {}",
                std::io::Error::last_os_error()
            )));
        }
        current = unsafe { File::from_raw_fd(fd) };
    }
    Ok(current)
}

#[cfg(not(unix))]
fn open_relative(_root: &File, _path: &Path, _directory: bool) -> Result<File, BoundedReadError> {
    Err(invalid(
        "rooted custody reads are unsupported on this platform",
    ))
}

fn validate_digest(value: &str) -> Result<(), BoundedReadError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("digest must be lowercase SHA-256"));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn invalid(message: impl Into<String>) -> BoundedReadError {
    BoundedReadError::InvalidCustody(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (tempfile::TempDir, BoundedReadSession) {
        let dir = tempfile::tempdir().unwrap();
        let content = vec![b'x'; 3_100];
        std::fs::write(dir.path().join("artifact.txt"), &content).unwrap();
        let manifest = json!({
            "schema": "bounded-read-v1",
            "request_id": "request",
            "project_id": "project",
            "revision": "revision",
            "entries": [{
                "artifact_id": "artifact",
                "path": "artifact.txt",
                "sha256": sha256_hex(&content),
                "size": content.len(),
                "media_type": "text/plain"
            }]
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let path = dir.path().join("manifest.json");
        std::fs::write(&path, &bytes).unwrap();
        let session = BoundedReadSession::load(
            &path,
            &sha256_hex(&bytes),
            "request".into(),
            "project".into(),
            "revision".into(),
            Instant::now(),
        )
        .unwrap();
        (dir, session)
    }

    #[test]
    fn pages_with_opaque_one_use_cursors_and_no_paths() {
        let (_dir, session) = fixture();
        let first = session.read_page("artifact", None).unwrap();
        assert_eq!(first.byte_start, 0);
        assert!(!first.end);
        let cursor = first.next_cursor.as_deref().unwrap();
        assert!(!cursor.contains("artifact.txt"));
        let second = session.read_page("artifact", Some(cursor)).unwrap();
        assert_eq!(second.byte_start, MAX_PAGE_CONTENT_BYTES as u64);
        assert!(matches!(
            session.read_page("artifact", Some(cursor)),
            Err(BoundedReadError::InvalidCustody(_))
        ));
        assert!(matches!(
            session.read_page("other", second.next_cursor.as_deref()),
            Err(BoundedReadError::InvalidCustody(_))
        ));
    }

    #[test]
    fn admission_enforces_each_cumulative_count_and_context_boundaries() {
        let (_dir, session) = fixture();
        assert!(session.admit_tool_result(MAX_TOOL_RESULT_BYTES).is_ok());
        assert!(session.admit_tool_result(MAX_TOOL_RESULT_BYTES).is_ok());
        assert!(session.admit_tool_result(MAX_TOOL_RESULT_BYTES).is_ok());
        assert!(session.admit_tool_result(MAX_TOOL_RESULT_BYTES).is_ok());
        assert_eq!(
            session.admit_tool_result(0).unwrap_err().code(),
            "budget-exhausted"
        );

        let (_dir, session) = fixture();
        for _ in 0..MAX_PROVIDER_REQUESTS {
            assert!(
                session
                    .admit_provider_request(MAX_PROVIDER_REQUEST_BYTES, 100_000)
                    .is_ok()
            );
        }
        assert_eq!(
            session
                .admit_provider_request(0, 100_000)
                .unwrap_err()
                .code(),
            "budget-exhausted"
        );
        let (_dir, session) = fixture();
        assert_eq!(
            session
                .admit_provider_request(
                    MAX_PROVIDER_REQUEST_BYTES,
                    MAX_PROVIDER_REQUEST_BYTES as u64
                        + MAX_OUTPUT_TOKENS
                        + PROVIDER_FRAMING_RESERVE
                        - 1,
                )
                .unwrap_err()
                .code(),
            "context-too-large"
        );
    }

    #[test]
    fn second_user_turn_is_refused_by_shared_session_state() {
        let (_dir, session) = fixture();
        assert!(session.begin_user_turn().is_ok());
        assert_eq!(
            session.begin_user_turn().unwrap_err().code(),
            "budget-exhausted"
        );
    }

    #[test]
    fn provider_request_requires_exact_single_custody_tool() {
        let (_dir, session) = fixture();
        let tool = json!({
            "type": "function",
            "name": "read_custodied_page",
            "description": "Read one bounded page from an allowlisted custodied request artifact.",
            "strict": true,
            "parameters": {
                "type": "object",
                "properties": {
                    "artifact_id": {"type": "string"},
                    "cursor": {"type": "string"}
                },
                "required": ["artifact_id"],
                "additionalProperties": false
            }
        });
        let encode = |tools: serde_json::Value| {
            serde_json::to_vec(&json!({
                "parallel_tool_calls": false,
                "tools": tools
            }))
            .unwrap()
        };
        assert!(
            session
                .validate_provider_request(&encode(json!([tool.clone()])))
                .is_ok()
        );
        assert!(
            session
                .validate_provider_request(&encode(json!([])))
                .is_err()
        );
        assert!(
            session
                .validate_provider_request(&encode(json!([tool.clone(), tool.clone()])))
                .is_err()
        );
        let mut wrong = tool;
        wrong["name"] = json!("exec_command");
        assert!(
            session
                .validate_provider_request(&encode(json!([wrong])))
                .is_err()
        );
    }

    #[test]
    fn custody_rejects_digest_binding_traversal_duplicates_and_symlinks() {
        let (dir, _session) = fixture();
        let manifest_path = dir.path().join("manifest.json");
        let bytes = std::fs::read(&manifest_path).unwrap();
        assert!(
            BoundedReadSession::load(
                &manifest_path,
                &"0".repeat(64),
                "request".into(),
                "project".into(),
                "revision".into(),
                Instant::now(),
            )
            .is_err()
        );

        let bad = |entry: serde_json::Value| {
            let manifest = json!({
                "schema": "bounded-read-v1",
                "request_id": "request",
                "project_id": "project",
                "revision": "revision",
                "entries": entry
            });
            let bytes = serde_json::to_vec(&manifest).unwrap();
            std::fs::write(&manifest_path, &bytes).unwrap();
            BoundedReadSession::load(
                &manifest_path,
                &sha256_hex(&bytes),
                "request".into(),
                "project".into(),
                "revision".into(),
                Instant::now(),
            )
        };
        let traversal = json!({
            "artifact_id": "artifact", "path": "../outside", "sha256": "0".repeat(64),
            "size": 0, "media_type": "text/plain"
        });
        assert!(bad(json!([traversal])).is_err());
        let valid = json!({
            "artifact_id": "artifact", "path": "artifact.txt", "sha256": sha256_hex(&vec![b'x'; 3_100]),
            "size": 3_100, "media_type": "text/plain"
        });
        assert!(bad(json!([valid.clone(), valid])).is_err());
        let same_path = json!({
            "artifact_id": "second", "path": "artifact.txt", "sha256": sha256_hex(&vec![b'x'; 3_100]),
            "size": 3_100, "media_type": "text/plain"
        });
        assert!(bad(json!([valid, same_path])).is_err());
        for (id, path) in [
            ("bad id", "artifact.txt"),
            ("safe", "dir//artifact.txt"),
            ("safe", "dir/./artifact.txt"),
        ] {
            let entry = json!({
                "artifact_id": id, "path": path, "sha256": "0".repeat(64),
                "size": 0, "media_type": "text/plain"
            });
            assert!(bad(json!([entry])).is_err());
        }

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("artifact.txt", dir.path().join("link.txt")).unwrap();
            let linked = json!([{
                "artifact_id": "linked", "path": "link.txt", "sha256": sha256_hex(b"x"),
                "size": 1, "media_type": "text/plain"
            }]);
            assert!(bad(linked).is_err());
        }
        assert!(!bytes.is_empty());
    }

    #[test]
    fn verified_artifact_is_immutable_for_the_session() {
        let (dir, session) = fixture();
        std::fs::write(dir.path().join("artifact.txt"), vec![b'y'; 3_100]).unwrap();
        let page = session.read_page("artifact", None).unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(page.content_base64)
            .unwrap();
        assert_eq!(decoded, vec![b'x'; MAX_PAGE_CONTENT_BYTES]);
    }

    #[test]
    fn manifest_limits_are_checked_before_artifact_opens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        let load = |entries: Vec<serde_json::Value>| {
            let bytes = serde_json::to_vec(&json!({
                "schema": "bounded-read-v1", "request_id": "request",
                "project_id": "project", "revision": "revision", "entries": entries
            }))
            .unwrap();
            std::fs::write(&path, &bytes).unwrap();
            BoundedReadSession::load(
                &path,
                &sha256_hex(&bytes),
                "request".into(),
                "project".into(),
                "revision".into(),
                Instant::now(),
            )
        };
        let entry = |index: usize, size: u64| {
            json!({
                "artifact_id": format!("a{index}"), "path": format!("missing{index}"),
                "sha256": "0".repeat(64), "size": size, "media_type": "text/plain"
            })
        };
        let too_many = load((0..=MAX_ARTIFACTS).map(|i| entry(i, 0)).collect()).unwrap_err();
        assert!(too_many.to_string().contains("too many artifacts"));
        let too_large = load((0..5).map(|i| entry(i, MAX_ARTIFACT_BYTES)).collect()).unwrap_err();
        assert!(too_large.to_string().contains("aggregate artifact size"));
    }

    #[cfg(unix)]
    #[test]
    fn rooted_open_rejects_symlinked_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let content = b"outside";
        std::fs::write(outside.path().join("artifact.txt"), content).unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("linked")).unwrap();
        let manifest = json!({
            "schema": "bounded-read-v1", "request_id": "request",
            "project_id": "project", "revision": "revision", "entries": [{
                "artifact_id": "artifact", "path": "linked/artifact.txt",
                "sha256": sha256_hex(content), "size": content.len(), "media_type": "text/plain"
            }]
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let path = dir.path().join("manifest.json");
        std::fs::write(&path, &bytes).unwrap();
        assert!(
            BoundedReadSession::load(
                &path,
                &sha256_hex(&bytes),
                "request".into(),
                "project".into(),
                "revision".into(),
                Instant::now(),
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn rooted_open_rejects_fifo_without_blocking() {
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("artifact.pipe");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let manifest = json!({
            "schema": "bounded-read-v1", "request_id": "request",
            "project_id": "project", "revision": "revision", "entries": [{
                "artifact_id": "artifact", "path": "artifact.pipe",
                "sha256": "0".repeat(64), "size": 1, "media_type": "text/plain"
            }]
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let path = dir.path().join("manifest.json");
        std::fs::write(&path, &bytes).unwrap();
        let started = Instant::now();
        let error = BoundedReadSession::load(
            &path,
            &sha256_hex(&bytes),
            "request".into(),
            "project".into(),
            "revision".into(),
            Instant::now(),
        )
        .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(
            error.to_string().contains("not a declared regular file"),
            "unexpected FIFO error: {error}"
        );
    }

    #[test]
    fn expired_session_refuses_without_consuming_quota() {
        let (dir, _) = fixture();
        let path = dir.path().join("manifest.json");
        let bytes = std::fs::read(&path).unwrap();
        let session = BoundedReadSession::load(
            &path,
            &sha256_hex(&bytes),
            "request".into(),
            "project".into(),
            "revision".into(),
            Instant::now() - DEADLINE - Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(
            session.admit_tool_result(1).unwrap_err().code(),
            "deadline-exceeded"
        );
        assert_eq!(
            session
                .admit_provider_request(1, 100_000)
                .unwrap_err()
                .code(),
            "deadline-exceeded"
        );
    }
}
