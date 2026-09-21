#![cfg(target_os = "linux")]

use anyhow::Result;
use codex_core::TurnInputRequest;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::SessionSource;
use codex_protocol::user_input::UserInput;
use core_test_support::responses::ev_assistant_message;
use core_test_support::responses::ev_completed;
use core_test_support::responses::ev_function_call;
use core_test_support::responses::ev_response_created;
use core_test_support::responses::mount_response_once;
use core_test_support::responses::mount_sse_sequence;
use core_test_support::responses::sse;
use core_test_support::responses::sse_response;
use core_test_support::responses::start_mock_server;
use core_test_support::test_codex::test_codex;
use core_test_support::wait_for_event;
use serde_json::Value;
use serde_json::json;
use serial_test::serial;
use sha2::Digest;
use sha2::Sha256;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::time::Duration;

const ENV_KEYS: [&str; 5] = [
    "CODEX_BOUNDED_READ_MANIFEST",
    "CODEX_BOUNDED_READ_MANIFEST_SHA256",
    "CODEX_BOUNDED_READ_REQUEST_ID",
    "CODEX_BOUNDED_READ_PROJECT_ID",
    "CODEX_BOUNDED_READ_REVISION",
];

struct EnvGuard(Vec<(&'static str, Option<OsString>)>);

impl EnvGuard {
    fn unset() -> Self {
        let old = ENV_KEYS
            .iter()
            .map(|key| (*key, std::env::var_os(key)))
            .collect();
        for key in ENV_KEYS {
            unsafe { std::env::remove_var(key) };
        }
        Self(old)
    }

    fn set_one(key: &'static str, value: &OsStr) -> Self {
        let old = vec![(key, std::env::var_os(key))];
        unsafe { std::env::set_var(key, value) };
        Self(old)
    }

    fn set(values: [(&'static str, &OsStr); 5]) -> Self {
        let old = values
            .iter()
            .map(|(key, _)| (*key, std::env::var_os(key)))
            .collect();
        for (key, value) in values {
            unsafe { std::env::set_var(key, value) };
        }
        Self(old)
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in self.0.drain(..) {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn custody_env(dir: &tempfile::TempDir, artifact_id: &str, content: &[u8]) -> EnvGuard {
    let artifact = dir.path().join("artifact.txt");
    std::fs::write(&artifact, content).unwrap();
    let manifest = serde_json::to_vec(&json!({
        "schema": "bounded-read-v1",
        "request_id": "request",
        "project_id": "project",
        "revision": "revision",
        "entries": [{
            "artifact_id": artifact_id,
            "path": "artifact.txt",
            "sha256": sha256(content),
            "size": content.len(),
            "media_type": "text/plain"
        }]
    }))
    .unwrap();
    let manifest_path = dir.path().join("manifest.json");
    std::fs::write(&manifest_path, &manifest).unwrap();
    let digest = sha256(&manifest);
    EnvGuard::set([
        (ENV_KEYS[0], manifest_path.as_os_str()),
        (ENV_KEYS[1], OsStr::new(&digest)),
        (ENV_KEYS[2], OsStr::new("request")),
        (ENV_KEYS[3], OsStr::new("project")),
        (ENV_KEYS[4], OsStr::new("revision")),
    ])
}

fn tool_names(body: &Value) -> Vec<&str> {
    body["tools"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|tool| tool["name"].as_str())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(bounded_read_env)]
async fn normal_mode_allows_two_user_turn_posts_when_custody_env_is_absent() -> Result<()> {
    let _env = EnvGuard::unset();
    let server = start_mock_server().await;
    let responses = mount_sse_sequence(
        &server,
        vec![
            sse(vec![
                ev_response_created("resp-normal-1"),
                ev_assistant_message("msg-normal-1", "first"),
                ev_completed("resp-normal-1"),
            ]),
            sse(vec![
                ev_response_created("resp-normal-2"),
                ev_assistant_message("msg-normal-2", "second"),
                ev_completed("resp-normal-2"),
            ]),
        ],
    )
    .await;
    let fixture = test_codex().with_model("gpt-5.4").build(&server).await?;
    for text in ["first", "second"] {
        fixture
            .codex
            .start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
                text: text.into(),
                text_elements: Vec::new(),
            }]))
            .await?;
        let terminal = wait_for_event(&fixture.codex, |event| {
            matches!(event, EventMsg::TurnComplete(_) | EventMsg::Error(_))
        })
        .await;
        assert!(matches!(terminal, EventMsg::TurnComplete(_)));
    }
    assert_eq!(responses.requests().len(), 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(bounded_read_env)]
async fn incomplete_custody_fails_during_session_spawn() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let manifest_path = dir.path().join("manifest.json");
    std::fs::write(&manifest_path, b"{}")?;
    let _env = EnvGuard::set_one(ENV_KEYS[0], manifest_path.as_os_str());
    let server = start_mock_server().await;

    let error = match test_codex().with_model("gpt-5.4").build(&server).await {
        Ok(_) => anyhow::bail!("incomplete custody unexpectedly started a session"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("bounded read environment is incomplete")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(bounded_read_env)]
async fn bounded_read_performs_exactly_two_posts_with_one_custody_tool() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let artifact_id = "artifact";
    let _env = custody_env(&dir, artifact_id, b"custodied evidence");

    let server = start_mock_server().await;
    let responses = mount_sse_sequence(
        &server,
        vec![
            sse(vec![
                ev_response_created("resp-1"),
                ev_function_call(
                    "read-1",
                    "read_custodied_page",
                    &json!({"artifact_id": artifact_id, "cursor": null}).to_string(),
                ),
                ev_completed("resp-1"),
            ]),
            sse(vec![
                ev_response_created("resp-2"),
                ev_assistant_message("msg-2", "done"),
                ev_completed("resp-2"),
            ]),
        ],
    )
    .await;

    let fixture = test_codex().with_model("gpt-5.4").build(&server).await?;
    fixture
        .codex
        .start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
            text: "consult the custodied artifact".into(),
            text_elements: Vec::new(),
        }]))
        .await?;
    let terminal = wait_for_event(&fixture.codex, |event| {
        matches!(event, EventMsg::TurnComplete(_) | EventMsg::Error(_))
    })
    .await;
    assert!(
        matches!(terminal, EventMsg::TurnComplete(_)),
        "unexpected terminal: {terminal:?}"
    );

    let requests = responses.requests();
    assert_eq!(requests.len(), 2);
    for request in &requests {
        assert_eq!(
            tool_names(&request.body_json()),
            vec!["read_custodied_page"]
        );
        assert_eq!(request.body_json()["parallel_tool_calls"], false);
    }
    let second = requests[1].body_json().to_string();
    assert!(second.contains("custodied evidence") || second.contains("Y3VzdG9kaWVkIGV2aWRlbmNl"));
    assert!(second.contains(artifact_id));
    assert!(!second.contains("artifact.txt"));
    assert!(!second.contains("manifest.json"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(bounded_read_env)]
async fn vscode_primary_session_is_admitted() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let _env = custody_env(&dir, "artifact", b"evidence");
    let server = start_mock_server().await;
    let responses = mount_sse_sequence(
        &server,
        vec![sse(vec![
            ev_response_created("resp-vscode"),
            ev_assistant_message("msg-vscode", "done"),
            ev_completed("resp-vscode"),
        ])],
    )
    .await;
    let fixture = test_codex()
        .with_model("gpt-5.4")
        .with_session_source(SessionSource::VSCode)
        .build(&server)
        .await?;
    fixture
        .codex
        .start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
            text: "answer".into(),
            text_elements: Vec::new(),
        }]))
        .await?;
    let terminal = wait_for_event(&fixture.codex, |event| {
        matches!(event, EventMsg::TurnComplete(_) | EventMsg::Error(_))
    })
    .await;
    assert!(matches!(terminal, EventMsg::TurnComplete(_)));
    assert_eq!(responses.requests().len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(bounded_read_env)]
async fn established_stream_failure_is_recovery_required_without_retry() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let _env = custody_env(&dir, "artifact", b"evidence");
    let server = start_mock_server().await;
    let responses = mount_sse_sequence(
        &server,
        vec![sse(vec![ev_response_created("resp-ambiguous")])],
    )
    .await;
    let fixture = test_codex().with_model("gpt-5.4").build(&server).await?;
    fixture
        .codex
        .start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
            text: "read".into(),
            text_elements: Vec::new(),
        }]))
        .await?;
    let terminal = wait_for_event(&fixture.codex, |event| {
        matches!(event, EventMsg::TurnComplete(_) | EventMsg::Error(_))
    })
    .await;
    assert!(matches!(terminal, EventMsg::Error(_)));
    assert!(format!("{terminal:?}").contains("recovery-required"));
    assert_eq!(responses.requests().len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(bounded_read_env)]
async fn second_user_turn_is_rejected_before_another_post() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let _env = custody_env(&dir, "artifact", b"evidence");
    let server = start_mock_server().await;
    let responses = mount_sse_sequence(
        &server,
        vec![sse(vec![
            ev_response_created("resp-1"),
            ev_assistant_message("msg-1", "done"),
            ev_completed("resp-1"),
        ])],
    )
    .await;
    let fixture = test_codex().with_model("gpt-5.4").build(&server).await?;
    for text in ["first", "second"] {
        fixture
            .codex
            .start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
                text: text.into(),
                text_elements: Vec::new(),
            }]))
            .await?;
        let terminal = wait_for_event(&fixture.codex, |event| {
            matches!(event, EventMsg::TurnComplete(_) | EventMsg::Error(_))
        })
        .await;
        if text == "first" {
            assert!(matches!(terminal, EventMsg::TurnComplete(_)));
        } else {
            assert!(matches!(terminal, EventMsg::Error(_)));
            assert!(format!("{terminal:?}").contains("budget-exhausted"));
        }
    }
    assert_eq!(responses.requests().len(), 1);
    Ok(())
}

#[tokio::test]
#[serial(bounded_read_env)]
async fn stalled_stream_is_cut_off_by_session_deadline() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let _env = custody_env(&dir, "artifact", b"evidence");
    let server = start_mock_server().await;
    let responses = mount_response_once(
        &server,
        sse_response(sse(vec![
            ev_response_created("resp-late"),
            ev_assistant_message("msg-late", "too late"),
            ev_completed("resp-late"),
        ]))
        .set_delay(Duration::from_secs(15 * 60 + 1)),
    )
    .await;
    let fixture = test_codex().with_model("gpt-5.4").build(&server).await?;
    tokio::time::pause();
    fixture
        .codex
        .start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
            text: "wait".into(),
            text_elements: Vec::new(),
        }]))
        .await?;
    for _ in 0..1_000 {
        if responses.requests().len() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        responses.requests().len(),
        1,
        "request never reached server"
    );
    tokio::time::advance(Duration::from_secs(15 * 60 + 1)).await;
    tokio::time::resume();
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    let terminal = wait_for_event(&fixture.codex, |event| {
        matches!(event, EventMsg::TurnComplete(_) | EventMsg::Error(_))
    })
    .await;
    assert!(matches!(terminal, EventMsg::Error(_)));
    assert!(format!("{terminal:?}").contains("deadline-exceeded"));
    assert_eq!(responses.requests().len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial(bounded_read_env)]
async fn oversized_serialized_tool_output_stops_before_second_post() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let artifact_id = "artifact";
    let call_id = "c".repeat(1_024);
    let _env = custody_env(&dir, artifact_id, &[b'x'; 1024]);

    let server = start_mock_server().await;
    let responses = mount_sse_sequence(
        &server,
        vec![sse(vec![
            ev_response_created("resp-1"),
            ev_function_call(
                &call_id,
                "read_custodied_page",
                &json!({"artifact_id": artifact_id, "cursor": null}).to_string(),
            ),
            ev_completed("resp-1"),
        ])],
    )
    .await;

    let fixture = test_codex().with_model("gpt-5.4").build(&server).await?;
    fixture
        .codex
        .start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
            text: "read".into(),
            text_elements: Vec::new(),
        }]))
        .await?;
    let terminal = wait_for_event(&fixture.codex, |event| {
        matches!(event, EventMsg::TurnComplete(_) | EventMsg::Error(_))
    })
    .await;
    assert!(
        matches!(terminal, EventMsg::Error(_)),
        "unexpected terminal: {terminal:?}"
    );
    assert_eq!(
        responses.requests().len(),
        1,
        "unexpected request count for terminal: {terminal:?}"
    );
    assert!(
        format!("{terminal:?}").contains("budget-exhausted"),
        "unexpected terminal: {terminal:?}"
    );
    Ok(())
}
