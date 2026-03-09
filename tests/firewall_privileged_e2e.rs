use std::process::{Command, Output};

fn opn_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_opn"));
    cmd.env("NO_COLOR", "1");
    cmd
}

fn assert_non_error_exit(output: &Output) {
    let code = output.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 1,
        "expected exit code 0/1, got {} stderr={}",
        code,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_non_error_or_missing_chain(output: &Output) {
    let code = output.status.code().unwrap_or(-1);
    if code == 0 || code == 1 {
        return;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let missing_chain = stderr.contains("No chain/target/match by that name")
        || stderr.contains("Chain 'OPN' does not exist")
        || stderr.contains("No chain/target/match");
    assert!(
        missing_chain,
        "expected success or missing-chain case, got {} stderr={}",
        code, stderr
    );
}

fn should_run_privileged() -> bool {
    std::env::var("OPN_RUN_PRIVILEGED_TESTS").as_deref() == Ok("1")
}

fn skip_if_not_privileged() -> bool {
    if !should_run_privileged() {
        eprintln!("skipping privileged firewall test: set OPN_RUN_PRIVILEGED_TESTS=1");
        return true;
    }
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping privileged firewall test: must run as root");
        return true;
    }
    false
}

#[test]
#[ignore = "requires root and OPN_RUN_PRIVILEGED_TESTS=1"]
fn test_firewall_list_flush_round_trip() {
    if skip_if_not_privileged() {
        return;
    }
    let flush = opn_cmd()
        .args(["--allow-write", "firewall", "flush"])
        .output()
        .expect("failed to run firewall flush");
    assert_non_error_or_missing_chain(&flush);

    let list = opn_cmd()
        .args(["--allow-write", "firewall", "list"])
        .output()
        .expect("failed to run firewall list");
    assert_non_error_exit(&list);
}

#[test]
#[ignore = "requires root and OPN_RUN_PRIVILEGED_TESTS=1"]
fn test_firewall_block_unblock_local_ip() {
    if skip_if_not_privileged() {
        return;
    }
    let block = opn_cmd()
        .args([
            "--allow-write",
            "firewall",
            "block-ip",
            "127.0.0.2",
            "--comment",
            "opn-test",
        ])
        .output()
        .expect("failed to run firewall block-ip");
    assert_non_error_exit(&block);

    let unblock = opn_cmd()
        .args(["--allow-write", "firewall", "unblock", "opn-test"])
        .output()
        .expect("failed to run firewall unblock");
    assert_non_error_exit(&unblock);
}
