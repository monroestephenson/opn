use std::process::Command;

fn opn_bin() -> &'static str {
    env!("CARGO_BIN_EXE_opn")
}

fn should_run_tty_tests() -> bool {
    std::env::var("OPN_RUN_TTY_TESTS").as_deref() == Ok("1")
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires OPN_RUN_TTY_TESTS=1 and script(1)"]
fn test_watch_tty_quit_linux() {
    if !should_run_tty_tests() {
        eprintln!("skipping tty watch test: set OPN_RUN_TTY_TESTS=1");
        return;
    }

    let cmd = format!("printf q | '{}' watch --interval 1", opn_bin());
    let output = Command::new("script")
        .args(["-qec", &cmd, "/dev/null"])
        .output()
        .expect("failed to run script tty harness");

    let code = output.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 1,
        "unexpected exit code {code}, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires OPN_RUN_TTY_TESTS=1 and script(1)"]
fn test_watch_tty_quit_macos() {
    if !should_run_tty_tests() {
        eprintln!("skipping tty watch test: set OPN_RUN_TTY_TESTS=1");
        return;
    }

    let cmd = format!("printf q | '{}' watch --interval 1", opn_bin());
    let output = Command::new("script")
        .args(["-q", "/dev/null", "sh", "-c", &cmd])
        .output()
        .expect("failed to run script tty harness");

    let code = output.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 1,
        "unexpected exit code {code}, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
