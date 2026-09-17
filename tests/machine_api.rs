#![cfg(all(unix, not(target_os = "macos")))]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const PROFILE_ID: &str = "0123456789abcdef0123456789abcdef";
const SSH: &str = r#"#!/bin/sh
for arg do
    last=$arg
    printf '%s\n' "$arg" >> "$TEST_ROOT/ssh-args"
done
case "$last" in
    *'command -v herdr') printf 'login banner\nherdr-remote-output-ready:1\n%s\n' "$TEST_REMOTE_HERDR" ;;
    *'remote-api-bridge --check')
        if [ "$TEST_MODE" = old ]; then exit 2; fi
        exec /bin/sh -c "$last" ;;
    *'remote-api-bridge')
        if [ "$TEST_MODE" = offline ]; then echo 'test remote connection failed' >&2; exit 255; fi
        exec /bin/sh -c "$last" ;;
    '/bin/sh -s')
        script=$(cat)
        printf 'login banner\nherdr-remote-output-ready:1\n'
        case "$script" in
            *'uname -s'*) uname -s; uname -m ;;
            *'version='*) printf '%s\n' "$TEST_REMOTE_HERDR" ;;
            *) echo "unexpected discovery: $script" >&2; exit 2 ;;
        esac ;;
    *) echo "unexpected command: $last" >&2; exit 2 ;;
esac
"#;

struct Harness {
    root: PathBuf,
    remote: UnixListener,
    local: UnixListener,
    protocol: u64,
}

impl Harness {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = PathBuf::from(format!(
            "/var/tmp/hma-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let app = if cfg!(debug_assertions) {
            "herdr-dev"
        } else {
            "herdr"
        };
        let state = root.join("state").join(app).join("client");
        let session = root.join("config").join(app).join("sessions/fleet");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&session).unwrap();
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("bin/ssh"), SSH).unwrap();
        fs::set_permissions(root.join("bin/ssh"), fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_herdr"), root.join("remote herdr")).unwrap();
        fs::write(state.join("endpoints.json"), serde_json::to_vec(&json!({
            "version": 1,
            "ssh": [{"id": PROFILE_ID, "label": "mac", "target": "fake-mac", "session": "fleet", "enabled": true}]
        })).unwrap()).unwrap();
        let remote = UnixListener::bind(session.join("herdr.sock")).unwrap();
        remote.set_nonblocking(true).unwrap();
        let local = UnixListener::bind(root.join("local.sock")).unwrap();
        local.set_nonblocking(true).unwrap();
        let status = Command::new(env!("CARGO_BIN_EXE_herdr"))
            .args(["status", "client", "--json"])
            .output()
            .unwrap();
        let status: Value = serde_json::from_slice(&status.stdout).unwrap();
        Self {
            root,
            remote,
            local,
            protocol: status["protocol"].as_u64().unwrap(),
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_herdr"));
        command
            .args(args)
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.root.join("bin").display()),
            )
            .env("HOME", &self.root)
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("XDG_RUNTIME_DIR", &self.root)
            .env("TEST_ROOT", &self.root)
            .env("TEST_REMOTE_HERDR", self.root.join("remote herdr"))
            .env("HERDR_SOCKET_PATH", self.root.join("local.sock"))
            .env(
                "HERDR_CLIENT_SOCKET_PATH",
                self.root.join("never-client.sock"),
            )
            .env("HERDR_SESSION", "wrong-inherited-session")
            .env("HERDR_PANE_ID", "wrong-local-pane")
            .env_remove("HERDR_CONFIG_PATH")
            .env_remove("HERDR_REMOTE_BINARY");
        command
    }

    fn serve(&self, result: Value, protocol: u64) -> std::thread::JoinHandle<Value> {
        let listener = self.remote.try_clone().unwrap();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "remote API request did not arrive"
                        );
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("{error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut line = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                let request: Value = serde_json::from_str(&line).unwrap();
                let ping = request["method"] == "ping";
                let response = if ping {
                    json!({"id": request["id"], "result": {"type": "pong", "version": "test", "protocol": protocol}})
                } else {
                    std::thread::sleep(Duration::from_millis(50));
                    let mut response = result.clone();
                    response["id"] = request["id"].clone();
                    response
                };
                writeln!(stream, "{response}").unwrap();
                if !ping || protocol == 0 {
                    return request;
                }
            }
        })
    }

    fn assert_local_untouched(&self) {
        assert_eq!(
            self.local.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(!self.root.join("never-client.sock").exists());
        assert!(!fs::read_dir(&self.root).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("herdr-api-")));
    }

    fn assert_no_machine_connection(&self) {
        self.assert_local_untouched();
        assert!(!self.root.join("ssh-args").exists());
        assert_eq!(
            self.remote.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    fn catalog_path(&self) -> PathBuf {
        let app = if cfg!(debug_assertions) {
            "herdr-dev"
        } else {
            "herdr"
        };
        self.root.join("state").join(app).join("client")
    }

    fn write_catalog(&self, body: Value) {
        fs::write(
            self.catalog_path().join("endpoints.json"),
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
    }

    fn write_selection(&self, name: &str, body: Value) {
        let dir = self.catalog_path().join("endpoint-selections");
        fs::create_dir_all(&dir).unwrap();
        let file = if name == "default" {
            "session-64656661756c74.json".to_string()
        } else {
            encoded_selection_file(name)
        };
        fs::write(dir.join(file), serde_json::to_vec(&body).unwrap()).unwrap();
    }

    fn write_legacy_selection(&self, body: Value) {
        fs::write(
            self.catalog_path().join("endpoint-selection.json"),
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
    }
}

fn encoded_selection_file(name: &str) -> String {
    let mut encoded = String::from("session-");
    for byte in name.as_bytes() {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded.push_str(".json");
    encoded
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn bounded_output(mut command: Command) -> Output {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn machine command");
    let timeout = Duration::from_secs(5);
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap_or_else(|error| {
                    panic!("failed to collect timed-out machine command: {error}")
                });
                panic!(
                    "machine command exceeded {timeout:?} without exiting; unexpected SSH/dispatch? stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(error) => panic!("failed to wait for machine command: {error}"),
        }
    }
    child
        .wait_with_output()
        .expect("collect machine command output")
}

fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn machine_api_routes_structured_payload_and_remote_errors_without_local_fallback() {
    let harness = Harness::new();
    let server = harness.serve(
        json!({"error":{"code":"test_remote_error","message":"remote rejected prompt"}}),
        harness.protocol,
    );
    let prompt = "quotes ' \" ; $(touch should-not-exist)\n--machine other";
    let output = harness
        .command(&["--machine", "mac", "agent", "prompt", "w4:p1", prompt])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let error: Value = serde_json::from_slice(&output.stderr)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stderr)));
    assert_eq!(error["error"]["code"], "test_remote_error");
    let request = server.join().unwrap();
    assert_eq!(request["method"], "agent.prompt");
    assert_eq!(request["params"]["text"], prompt);
    let ssh_args = fs::read_to_string(harness.root.join("ssh-args")).unwrap();
    assert!(ssh_args.contains("StrictHostKeyChecking=yes"));
    assert!(ssh_args.contains("BatchMode=yes"));
    assert!(ssh_args.contains("--session fleet remote-api-bridge"));
    assert!(!ssh_args.contains("should-not-exist"));
    harness.assert_local_untouched();
}

#[test]
fn machine_api_profile_id_routes_large_list_responses() {
    let harness = Harness::new();
    let data = "remote data ".repeat(20_000);
    let server = harness.serve(
        json!({"result":{"type":"agent_list","agents":[],"test_data":data}}),
        harness.protocol,
    );
    let response = success(
        harness
            .command(&["--machine", PROFILE_ID, "agent", "list"])
            .output()
            .unwrap(),
    );
    assert_eq!(response["result"]["test_data"], data);
    assert_eq!(server.join().unwrap()["method"], "agent.list");
    harness.assert_local_untouched();
}

#[test]
fn machine_api_never_inherits_the_callers_pane() {
    let harness = Harness::new();
    let server = harness.serve(json!({"result":{"type":"ok"}}), harness.protocol);
    success(
        harness
            .command(&["--machine=mac", "pane", "current"])
            .output()
            .unwrap(),
    );
    let request = server.join().unwrap();
    assert_eq!(request["method"], "pane.current");
    assert!(request["params"]["caller_pane_id"].is_null());
    harness.assert_local_untouched();
}

#[test]
fn machine_api_remote_paths_and_wait_parameters_reach_the_server() {
    for (args, method, expected) in [
        (
            vec![
                "worktree",
                "create",
                "--cwd",
                "~/Projects/herdr",
                "--branch",
                "review",
                "--path",
                "/srv/review",
            ],
            "worktree.create",
            json!({"cwd":"~/Projects/herdr", "branch":"review", "path":"/srv/review"}),
        ),
        (
            vec![
                "agent",
                "wait",
                "w4:p1",
                "--until",
                "idle",
                "--timeout",
                "2000",
            ],
            "agent.wait",
            json!({"target":"w4:p1", "until":["idle"], "timeout_ms":2000}),
        ),
    ] {
        let harness = Harness::new();
        let server = harness.serve(json!({"result":{"type":"ok"}}), harness.protocol);
        let mut command = harness.command(&["--machine", "mac"]);
        success(command.args(args).output().unwrap());
        let request = server.join().unwrap();
        assert_eq!(request["method"], method);
        for (key, value) in expected.as_object().unwrap() {
            assert_eq!(&request["params"][key], value);
        }
        harness.assert_local_untouched();
    }
}

#[test]
fn machine_api_status_reports_remote_identity_not_local_installation_state() {
    let harness = Harness::new();
    let server = harness.serve(json!({}), 0);
    let status = success(
        harness
            .command(&["--machine", "mac", "status", "server", "--json"])
            .output()
            .unwrap(),
    );
    assert_eq!(status["session"], "fleet");
    assert_eq!(status["socket"], format!("machine:{PROFILE_ID}/fleet"));
    assert!(status["server_binary_stale"].is_null());
    assert_eq!(server.join().unwrap()["method"], "ping");
    harness.assert_local_untouched();
}

#[test]
fn machine_api_usage_errors_do_not_connect() {
    let harness = Harness::new();
    for args in [
        vec!["--machine", "missing", "agent", "list"],
        vec!["--machine", "mac", "config", "reset-keys"],
        vec![
            "--machine",
            "mac",
            "agent",
            "explain",
            "--file",
            "/any/file",
            "--agent",
            "pi",
        ],
        vec![
            "--machine",
            "mac",
            "pane",
            "split",
            "--current",
            "--direction",
            "right",
        ],
        vec!["--machine", "mac", "--session", "local", "agent", "list"],
    ] {
        assert_eq!(
            harness.command(&args).output().unwrap().status.code(),
            Some(2)
        );
    }
    assert!(!harness.root.join("ssh-args").exists());
    harness.assert_local_untouched();
}

#[test]
fn machine_api_rejects_old_bridges_and_disconnected_machines() {
    for (mode, message) in [
        ("old", "update Herdr"),
        ("offline", "test remote connection failed"),
    ] {
        let harness = Harness::new();
        let output = harness
            .command(&["--machine", "mac", "agent", "list"])
            .env("TEST_MODE", mode)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        harness.assert_local_untouched();
    }
}

#[test]
fn machine_api_server_stop_is_sent_only_to_the_selected_machine() {
    let harness = Harness::new();
    let server = harness.serve(json!({"result":{"type":"ok"}}), harness.protocol);
    let output = harness
        .command(&["--machine", "mac", "server", "stop"])
        .env("HERDR_SOCKET_PATH", harness.root.join("missing-local.sock"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        harness.root.join("ssh-args").exists(),
        "server stop bypassed machine routing"
    );
    assert_eq!(server.join().unwrap()["method"], "server.stop");
    harness.assert_local_untouched();
}

#[test]
fn machine_api_protocol_mismatch_never_sends_the_mutation() {
    let harness = Harness::new();
    let server = harness.serve(json!({}), 0);
    let output = harness
        .command(&["--machine", "mac", "pane", "close", "w4:p1"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(server.join().unwrap()["method"], "ping");
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("protocol_mismatch"), "{error}");
    assert!(error.contains("machine 'mac'"), "{error}");
    assert!(!error.contains("HERDR_SOCKET_PATH="), "{error}");
    harness.assert_local_untouched();
}

#[test]
fn machine_api_rejects_disallowed_and_invalid_context_without_ssh() {
    let harness = Harness::new();
    harness.write_catalog(json!({
        "version": 1,
        "ssh": [{
            "id": PROFILE_ID,
            "label": "mac",
            "target": "fake-mac",
            "session": "fleet",
            "enabled": true,
            "local_sessions": ["default"]
        }]
    }));

    let mut disallowed_cmd = harness.command(&["--machine", "mac", "agent", "list"]);
    disallowed_cmd.env("HERDR_SESSION", "sandbox");
    let disallowed = bounded_output(disallowed_cmd);
    assert_eq!(disallowed.status.code(), Some(2));
    let disallowed_err = String::from_utf8_lossy(&disallowed.stderr);
    assert!(
        disallowed_err.contains("not available in local session sandbox"),
        "{disallowed_err}"
    );
    assert!(
        disallowed_err.contains("machine availability"),
        "{disallowed_err}"
    );
    harness.assert_no_machine_connection();

    let mut invalid_cmd = harness.command(&["--machine", "mac", "agent", "list"]);
    invalid_cmd.env("HERDR_SESSION", "bad/name");
    let invalid = bounded_output(invalid_cmd);
    assert_eq!(invalid.status.code(), Some(2));
    let invalid_err = String::from_utf8_lossy(&invalid.stderr);
    assert!(invalid_err.contains("session name"), "{invalid_err}");
    harness.assert_no_machine_connection();
}

#[test]
fn machine_list_rejects_invalid_inherited_context_with_socket_override() {
    let harness = Harness::new();
    let mut list_cmd = harness.command(&["machine", "list", "--json"]);
    list_cmd.env("HERDR_SESSION", "bad/name");
    let output = bounded_output(list_cmd);
    assert_eq!(output.status.code(), Some(2));
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("session name"), "{err}");
    harness.assert_no_machine_connection();
}

#[test]
fn machine_api_disabled_and_ambiguous_errors_precede_availability() {
    let harness = Harness::new();
    harness.write_catalog(json!({
        "version": 1,
        "ssh": [
            {
                "id": PROFILE_ID,
                "label": "mac",
                "target": "fake-mac",
                "session": "fleet",
                "enabled": false,
                "local_sessions": ["default"]
            },
            {
                "id": "fedcba9876543210fedcba9876543210",
                "label": "mac",
                "target": "other-mac",
                "session": "fleet",
                "enabled": true,
                "local_sessions": ["default"]
            }
        ]
    }));
    let disabled = harness
        .command(&["--machine", PROFILE_ID, "agent", "list"])
        .env("HERDR_SESSION", "sandbox")
        .output()
        .unwrap();
    assert_eq!(disabled.status.code(), Some(2));
    let disabled_err = String::from_utf8_lossy(&disabled.stderr);
    assert!(disabled_err.contains("is disabled"), "{disabled_err}");
    assert!(!disabled_err.contains("not available"), "{disabled_err}");

    let ambiguous = harness
        .command(&["--machine", "mac", "agent", "list"])
        .env("HERDR_SESSION", "sandbox")
        .output()
        .unwrap();
    assert_eq!(ambiguous.status.code(), Some(2));
    let ambiguous_err = String::from_utf8_lossy(&ambiguous.stderr);
    assert!(ambiguous_err.contains("ambiguous"), "{ambiguous_err}");
    harness.assert_no_machine_connection();
}

#[test]
fn machine_list_json_uses_raw_profiles_and_scoped_preference() {
    let harness = Harness::new();
    let enabled_id = PROFILE_ID;
    let disabled_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let disallowed_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    harness.write_catalog(json!({
        "version": 1,
        "selected_profile": enabled_id,
        "ssh": [
            {
                "id": enabled_id,
                "label": "one",
                "target": "one",
                "session": "fleet",
                "enabled": true,
                "local_sessions": ["default", "sandbox"]
            },
            {
                "id": disabled_id,
                "label": "two",
                "target": "two",
                "session": "fleet",
                "enabled": false
            },
            {
                "id": disallowed_id,
                "label": "three",
                "target": "three",
                "session": "fleet",
                "enabled": true,
                "local_sessions": ["sandbox"]
            }
        ]
    }));
    harness.write_legacy_selection(json!({
        "version": 1,
        "selected_profile": disallowed_id
    }));
    harness.write_selection("default", json!({"version": 1, "selected_profile": null}));
    let catalog_before = fs::read(harness.catalog_path().join("endpoints.json")).unwrap();
    let legacy_before = fs::read(harness.catalog_path().join("endpoint-selection.json")).unwrap();
    let scoped_before = fs::read(
        harness
            .catalog_path()
            .join("endpoint-selections/session-64656661756c74.json"),
    )
    .unwrap();
    assert!(!harness
        .catalog_path()
        .join("endpoint-selections")
        .join(encoded_selection_file("sandbox"))
        .exists());

    let default_list = success(
        harness
            .command(&["machine", "list", "--json"])
            .env_remove("HERDR_SESSION")
            .output()
            .unwrap(),
    );
    assert_eq!(default_list.as_array().unwrap().len(), 3);
    assert_eq!(default_list[0]["id"], enabled_id);
    assert_eq!(default_list[0]["available"], true);
    assert_eq!(default_list[0]["selected"], false);
    assert_eq!(default_list[1]["id"], disabled_id);
    assert_eq!(default_list[1]["available"], false);
    assert_eq!(default_list[1]["selected"], false);
    assert_eq!(default_list[2]["id"], disallowed_id);
    assert_eq!(default_list[2]["available"], false);
    assert_eq!(default_list[2]["selected"], false);

    let named_list = success(
        harness
            .command(&["machine", "list", "--json"])
            .env("HERDR_SESSION", "sandbox")
            .output()
            .unwrap(),
    );
    assert_eq!(named_list[0]["available"], true);
    assert_eq!(named_list[0]["selected"], false);
    assert_eq!(named_list[1]["available"], false);
    assert_eq!(named_list[2]["available"], true);
    assert_eq!(named_list[2]["selected"], false);

    assert_eq!(
        fs::read(harness.catalog_path().join("endpoints.json")).unwrap(),
        catalog_before
    );
    assert_eq!(
        fs::read(harness.catalog_path().join("endpoint-selection.json")).unwrap(),
        legacy_before
    );
    assert_eq!(
        fs::read(
            harness
                .catalog_path()
                .join("endpoint-selections/session-64656661756c74.json")
        )
        .unwrap(),
        scoped_before
    );
    assert!(!harness
        .catalog_path()
        .join("endpoint-selections")
        .join(encoded_selection_file("sandbox"))
        .exists());
}
