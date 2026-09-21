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
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

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

#[derive(Default)]
#[derive(Debug)]
struct Admission {
    provider_requests: u8,
    provider_bytes: usize,
    pages: u8,
    tool_bytes: usize,
    issued_cursors: BTreeMap<String, Cursor>,
    consumed_cursors: HashSet<String>,
}

#[derive(Clone)]
#[derive(Debug)]
struct Cursor {
    artifact_id: String,
    offset: u64,
}

#[derive(Debug)]
pub(crate) struct BoundedReadSession {
    root: PathBuf,
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
        reject_symlink_components(manifest_path)?;
        let metadata = std::fs::symlink_metadata(manifest_path)
            .map_err(|error| invalid(format!("manifest metadata: {error}")))?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_MANIFEST_BYTES {
            return Err(invalid("manifest is not a bounded regular file"));
        }
        let bytes = read_bounded(manifest_path, MAX_MANIFEST_BYTES)?;
        if sha256_hex(&bytes) != expected_digest {
            return Err(invalid("manifest digest mismatch"));
        }
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|error| invalid(format!("manifest JSON: {error}")))?;
        if manifest.schema != "bounded-read-v1"
            || manifest.request_id != request_id
            || manifest.project_id != project_id
            || manifest.revision != revision
        {
            return Err(invalid("manifest binding mismatch"));
        }
        let root = manifest_path
            .parent()
            .ok_or_else(|| invalid("manifest has no parent"))?
            .canonicalize()
            .map_err(|error| invalid(format!("manifest root: {error}")))?;
        let mut entries = BTreeMap::new();
        let mut paths = HashSet::new();
        for entry in manifest.entries {
            validate_entry(&root, &entry)?;
            if !paths.insert(entry.path.clone()) {
                return Err(invalid("duplicate artifact path"));
            }
            if entries.insert(entry.artifact_id.clone(), entry).is_some() {
                return Err(invalid("duplicate artifact id"));
            }
        }
        let mut nonce = [0_u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        Ok(Self {
            root,
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
                let mut state = self.admission.lock().map_err(|_| invalid("admission lock poisoned"))?;
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
        let mut file = verified_artifact_file(&self.root, entry)?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| invalid(format!("artifact seek: {error}")))?;
        let remaining = entry.size - offset;
        let amount = usize::try_from(remaining.min(MAX_PAGE_CONTENT_BYTES as u64))
            .map_err(|_| invalid("page size conversion"))?;
        let mut content = vec![0_u8; amount];
        file.read_exact(&mut content)
            .map_err(|error| invalid(format!("artifact page read: {error}")))?;
        let end_offset = offset
            .checked_add(amount as u64)
            .ok_or(BoundedReadError::BudgetExhausted)?;
        let end = end_offset == entry.size;
        let next_cursor = if end {
            None
        } else {
            let token = self.cursor_token(artifact_id, end_offset);
            let mut state = self.admission.lock().map_err(|_| invalid("admission lock poisoned"))?;
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
        let mut state = self.admission.lock().map_err(|_| invalid("admission lock poisoned"))?;
        let pages = state.pages.checked_add(1).ok_or(BoundedReadError::BudgetExhausted)?;
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
        let mut state = self.admission.lock().map_err(|_| invalid("admission lock poisoned"))?;
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
        if self.started_at.elapsed() > DEADLINE {
            Err(BoundedReadError::DeadlineExceeded)
        } else {
            Ok(())
        }
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
                FunctionCallError::Fatal(format!("invalid-custody: invalid bounded read arguments: {error}"))
            })?;
            let page = self
                .session
                .read_page(&args.artifact_id, args.cursor.as_deref())
                .map_err(|error| FunctionCallError::Fatal(format!("{}: {error}", error.code())))?;
            let output = serde_json::to_string(&page).map_err(|error| {
                FunctionCallError::Fatal(format!("invalid-custody: failed to serialize page: {error}"))
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

fn validate_entry(root: &Path, entry: &ManifestEntry) -> Result<(), BoundedReadError> {
    if entry.artifact_id.is_empty() || entry.artifact_id.len() > 128 {
        return Err(invalid("invalid artifact id"));
    }
    validate_digest(&entry.sha256)?;
    if entry.size > MAX_ARTIFACT_BYTES || !entry.media_type.starts_with("text/") {
        return Err(invalid("unsupported artifact size or media type"));
    }
    verified_artifact_file(root, entry)?;
    Ok(())
}

fn verified_artifact_file(
    root: &Path,
    entry: &ManifestEntry,
) -> Result<File, BoundedReadError> {
    let path = checked_artifact_path(root, entry)?;
    let mut file = open_nofollow(&path)?;
    let metadata = file
        .metadata()
        .map_err(|error| invalid(format!("artifact metadata: {error}")))?;
    if !metadata.is_file() || metadata.len() != entry.size {
        return Err(invalid("artifact is not a declared regular file"));
    }
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| invalid(format!("artifact read: {error}")))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| invalid("artifact size overflow"))?;
        if total > entry.size {
            return Err(invalid("artifact exceeds declared size"));
        }
        hash.update(&buffer[..count]);
    }
    if total != entry.size || hex(&hash.finalize()) != entry.sha256 {
        return Err(invalid("artifact size or digest mismatch"));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| invalid(format!("artifact rewind: {error}")))?;
    Ok(file)
}

fn checked_artifact_path(root: &Path, entry: &ManifestEntry) -> Result<PathBuf, BoundedReadError> {
    let relative = Path::new(&entry.path);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(invalid("artifact path is not canonical relative"));
    }
    let path = root.join(relative);
    reject_symlink_components(&path)?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("artifact has no parent"))?
        .canonicalize()
        .map_err(|error| invalid(format!("artifact parent: {error}")))?;
    if !parent.starts_with(root) {
        return Err(invalid("artifact escapes manifest root"));
    }
    Ok(path)
}

fn reject_symlink_components(path: &Path) -> Result<(), BoundedReadError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(invalid("symlink component"));
            }
            Ok(_) => {}
            Err(error) => return Err(invalid(format!("path metadata: {error}"))),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn open_nofollow(path: &Path) -> Result<File, BoundedReadError> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| invalid(format!("open: {error}")))
}

#[cfg(not(unix))]
fn open_nofollow(path: &Path) -> Result<File, BoundedReadError> {
    reject_symlink_components(path)?;
    File::open(path).map_err(|error| invalid(format!("open: {error}")))
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, BoundedReadError> {
    let file = open_nofollow(path)?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| invalid(format!("bounded read: {error}")))?;
    if bytes.len() as u64 > limit {
        return Err(invalid("bounded file exceeds limit"));
    }
    Ok(bytes)
}

fn validate_digest(value: &str) -> Result<(), BoundedReadError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
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
            assert!(session
                .admit_provider_request(MAX_PROVIDER_REQUEST_BYTES, 100_000)
                .is_ok());
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
    fn custody_rejects_digest_binding_traversal_duplicates_and_symlinks() {
        let (dir, _session) = fixture();
        let manifest_path = dir.path().join("manifest.json");
        let bytes = std::fs::read(&manifest_path).unwrap();
        assert!(BoundedReadSession::load(
            &manifest_path,
            &"0".repeat(64),
            "request".into(),
            "project".into(),
            "revision".into(),
            Instant::now(),
        )
        .is_err());

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
        assert!(bad(json!([valid.clone(), valid.clone()])).is_err());
        let same_path = json!({
            "artifact_id": "second", "path": "artifact.txt", "sha256": sha256_hex(&vec![b'x'; 3_100]),
            "size": 3_100, "media_type": "text/plain"
        });
        assert!(bad(json!([valid, same_path])).is_err());

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
            session.admit_provider_request(1, 100_000).unwrap_err().code(),
            "deadline-exceeded"
        );
    }
}
