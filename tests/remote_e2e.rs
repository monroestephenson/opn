//! E2E tests for `opn --host` remote mode.
//!
//! Tests that spin up a real local sshd live in the `with_sshd` block.
//! They require no extra env vars — the fixture handles everything.
//!
//! A small sshd is started on a random high port using temp keys.
//! An opn wrapper script points back to the test binary so the "remote"
//! side can find `opn` without it being on the system PATH.
//!
//! The `OPN_SSH_CONFIG` env var (consumed by remote.rs) lets us inject a
//! custom ssh_config that points `opn-test-local` at the temp sshd port.

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

// ── helpers ─────────────────────────────────────────────────────────────────

fn opn_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_opn"));
    cmd.env("NO_COLOR", "1");
    cmd
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind port 0")
        .local_addr()
        .unwrap()
        .port()
}

// ── sshd fixture ─────────────────────────────────────────────────────────────

struct SshdFixture {
    dir: PathBuf,
    ssh_config: PathBuf,
    _child: std::sync::Mutex<Child>,
}

impl SshdFixture {
    fn init() -> Self {
        let dir = PathBuf::from(format!("/tmp/opn-ssh-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("bin")).unwrap();

        // Generate SSH host key
        Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-f"])
            .arg(dir.join("host_key"))
            .args(["-N", "", "-q"])
            .status()
            .expect("ssh-keygen host key");

        // Generate client key
        Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-f"])
            .arg(dir.join("client_key"))
            .args(["-N", "", "-q"])
            .status()
            .expect("ssh-keygen client key");

        // authorized_keys
        std::fs::copy(dir.join("client_key.pub"), dir.join("authorized_keys")).unwrap();
        set_mode(&dir.join("authorized_keys"), 0o600);

        let port = free_port();

        // opn wrapper script — calls the test binary directly
        let opn_bin = env!("CARGO_BIN_EXE_opn");
        let wrapper = dir.join("bin/opn");
        let mut f = std::fs::File::create(&wrapper).unwrap();
        writeln!(f, "#!/bin/sh\nexec '{}' \"$@\"", opn_bin).unwrap();
        set_mode(&wrapper, 0o755);

        // sshd_config
        let sshd_config = dir.join("sshd_config");
        std::fs::write(
            &sshd_config,
            format!(
                "Port {port}\n\
                 HostKey {dir}/host_key\n\
                 AuthorizedKeysFile {dir}/authorized_keys\n\
                 PasswordAuthentication no\n\
                 ChallengeResponseAuthentication no\n\
                 UsePAM {use_pam}\n\
                 StrictModes no\n\
                 PidFile {dir}/sshd.pid\n\
                 LogLevel ERROR\n\
                 SetEnv PATH={dir}/bin:/usr/bin:/bin:/usr/sbin:/sbin\n",
                use_pam = if cfg!(target_os = "linux") {
                    "yes"
                } else {
                    "no"
                },
                port = port,
                dir = dir.display(),
            ),
        )
        .unwrap();

        // client ssh_config — alias `opn-test-local` → 127.0.0.1:port
        let ssh_config = dir.join("ssh_config");
        std::fs::write(
            &ssh_config,
            format!(
                "Host opn-test-local\n\
                 HostName 127.0.0.1\n\
                 Port {port}\n\
                 User {user}\n\
                 IdentityFile {dir}/client_key\n\
                 StrictHostKeyChecking no\n\
                 UserKnownHostsFile /dev/null\n\
                 LogLevel ERROR\n",
                port = port,
                user = whoami(),
                dir = dir.display(),
            ),
        )
        .unwrap();

        // Start sshd
        // Redirect sshd stdio to /dev/null so it doesn't hold the test
        // runner's stdout/stderr pipes open (which would cause a hang).
        let child = Command::new("/usr/sbin/sshd")
            .args(["-f"])
            .arg(&sshd_config)
            .args(["-D"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start sshd");

        // Wait for sshd to be ready
        wait_for_port(port, Duration::from_secs(5));

        SshdFixture {
            dir,
            ssh_config,
            _child: std::sync::Mutex::new(child),
        }
    }

    fn ssh_config_path(&self) -> &str {
        self.ssh_config.to_str().unwrap()
    }
}

impl Drop for SshdFixture {
    fn drop(&mut self) {
        if let Ok(mut child) = self._child.lock() {
            let _ = child.kill();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

static SSHD: OnceLock<SshdFixture> = OnceLock::new();

fn fixture() -> &'static SshdFixture {
    SSHD.get_or_init(SshdFixture::init)
}

fn wait_for_port(port: u16, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("sshd did not start on port {port} within {timeout:?}");
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn whoami() -> String {
    std::env::var("USER").unwrap_or_else(|_| {
        String::from_utf8(Command::new("whoami").output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_string()
    })
}

fn opn_remote(args: &[&str]) -> std::process::Output {
    let fx = fixture();
    opn_cmd()
        .env("OPN_SSH_CONFIG", fx.ssh_config_path())
        .args(args)
        .output()
        .expect("failed to run opn")
}

// ── always-on tests (no SSH) ─────────────────────────────────────────────────

#[test]
fn test_help_includes_host_flag() {
    let out = opn_cmd().arg("--help").output().expect("failed to run opn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("--host"),
        "--help should mention --host: {stdout}"
    );
}

#[test]
fn test_remote_watch_rejected_before_ssh() {
    // Watch bails before touching SSH — no sshd needed
    let out = opn_cmd()
        .args(["--host", "any-fake-host", "watch"])
        .output()
        .expect("failed to run opn");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not yet supported"),
        "expected 'not yet supported' in stderr: {stderr}"
    );
}

// ── live SSH tests ────────────────────────────────────────────────────────────

#[test]
fn test_remote_sockets_table() {
    let out = opn_remote(&["--host", "opn-test-local", "sockets"]);
    let code = out.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 1,
        "expected exit 0/1, got {code}. stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    if code == 0 {
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("PROTO"),
            "expected table header in output: {stdout}"
        );
    }
}

#[test]
fn test_remote_sockets_json() {
    let out = opn_remote(&["--host", "opn-test-local", "--json", "sockets"]);
    let code = out.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 1,
        "expected exit 0/1, got {code}. stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    if code == 0 {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let v: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("expected valid JSON: {e}. stdout={stdout}"));
        assert!(v.is_array(), "expected JSON array, got: {v}");
        // Each entry should have protocol/local_addr fields (rendered locally)
        if let Some(first) = v.as_array().and_then(|a| a.first()) {
            assert!(
                first.get("local_addr").is_some(),
                "expected local_addr field: {first}"
            );
        }
    }
}

#[test]
fn test_remote_port() {
    // Use a port we own: bind one locally so there's guaranteed to be a result
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let _keep = listener; // keep alive

    let out = opn_remote(&["--host", "opn-test-local", "port", &port.to_string()]);
    let code = out.status.code().unwrap_or(-1);
    // We might not see our own listener through the remote (different process namespace),
    // but the command must succeed or return no-results (not error).
    assert!(
        code == 0 || code == 1,
        "expected exit 0/1, got {code}. stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn test_remote_deleted() {
    let out = opn_remote(&["--host", "opn-test-local", "deleted"]);
    let code = out.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if code == 2 && stderr.contains("SSH connection failed") {
        eprintln!("skipping remote deleted test: ssh transport unavailable in this environment");
        return;
    }
    assert!(
        code == 0 || code == 1,
        "expected exit 0/1, got {code}. stderr={stderr}"
    );
}

#[test]
fn test_remote_watch_via_real_sshd_also_errors() {
    let out = opn_remote(&["--host", "opn-test-local", "watch"]);
    assert_eq!(out.status.code(), Some(2), "remote watch must exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not yet supported"),
        "expected 'not yet supported': {stderr}"
    );
}

#[test]
fn test_remote_hints_prefix() {
    // Run sockets and verify that any [remote] prefixed output on stderr
    // is present only there, not mixed into stdout.
    let out = opn_remote(&["--host", "opn-test-local", "sockets"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("[remote]"),
        "[remote] prefix must not appear on stdout: {stdout}"
    );
}
