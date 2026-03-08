//! Benchmarks for opn platform operations and rendering.
//!
//! Run with: cargo bench
//! Compare against system tools manually:
//!   time lsof -i -P -n
//!   time opn sockets
//!   time ss -tulnp  (Linux only)

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::process::Command;

// We can't import from `open_tool` directly because the crate is a binary.
// Instead, benchmark the CLI binary invocation and compare with system tools.

fn bench_opn_sockets(c: &mut Criterion) {
    let opn = env!("CARGO_BIN_EXE_opn");

    let mut group = c.benchmark_group("sockets");

    group.bench_function("opn sockets --json", |b| {
        b.iter(|| {
            let output = Command::new(opn)
                .args(["sockets", "--json"])
                .output()
                .expect("failed to run opn");
            black_box(output.stdout);
        });
    });

    group.bench_function("opn sockets (table)", |b| {
        b.iter(|| {
            let output = Command::new(opn)
                .args(["sockets"])
                .output()
                .expect("failed to run opn");
            black_box(output.stdout);
        });
    });

    // Compare with lsof if available
    if Command::new("lsof").arg("-v").output().is_ok() {
        group.bench_function("lsof -i -P -n", |b| {
            b.iter(|| {
                let output = Command::new("lsof")
                    .args(["-i", "-P", "-n"])
                    .output()
                    .expect("failed to run lsof");
                black_box(output.stdout);
            });
        });
    }

    // Compare with ss on Linux
    #[cfg(target_os = "linux")]
    if Command::new("ss").arg("-V").output().is_ok() {
        group.bench_function("ss -tulnp", |b| {
            b.iter(|| {
                let output = Command::new("ss")
                    .args(["-tulnp"])
                    .output()
                    .expect("failed to run ss");
                black_box(output.stdout);
            });
        });
    }

    group.finish();
}

fn bench_opn_port(c: &mut Criterion) {
    let opn = env!("CARGO_BIN_EXE_opn");

    let mut group = c.benchmark_group("port_lookup");

    // Benchmark port lookup (port 0 = likely no results, fast path)
    group.bench_function("opn port 0 --json", |b| {
        b.iter(|| {
            let output = Command::new(opn)
                .args(["port", "0", "--json"])
                .output()
                .expect("failed to run opn");
            black_box(output.stdout);
        });
    });

    // Compare with lsof port lookup
    if Command::new("lsof").arg("-v").output().is_ok() {
        group.bench_function("lsof -i :0 -P -n", |b| {
            b.iter(|| {
                let output = Command::new("lsof")
                    .args(["-i", ":0", "-P", "-n"])
                    .output()
                    .expect("failed to run lsof");
                black_box(output.stdout);
            });
        });
    }

    group.finish();
}

fn bench_opn_pid(c: &mut Criterion) {
    let opn = env!("CARGO_BIN_EXE_opn");
    let my_pid = std::process::id().to_string();

    let mut group = c.benchmark_group("pid_lookup");

    group.bench_function("opn pid (self) --json", |b| {
        b.iter(|| {
            let output = Command::new(opn)
                .args(["pid", &my_pid, "--json"])
                .output()
                .expect("failed to run opn");
            black_box(output.stdout);
        });
    });

    // Compare with lsof
    if Command::new("lsof").arg("-v").output().is_ok() {
        group.bench_function("lsof -p (self)", |b| {
            let pid = std::process::id().to_string();
            b.iter(|| {
                let output = Command::new("lsof")
                    .args(["-p", &pid])
                    .output()
                    .expect("failed to run lsof");
                black_box(output.stdout);
            });
        });
    }

    group.finish();
}

fn bench_opn_file(c: &mut Criterion) {
    let opn = env!("CARGO_BIN_EXE_opn");

    let mut group = c.benchmark_group("file_lookup");

    group.bench_function("opn file /dev/null --json", |b| {
        b.iter(|| {
            let output = Command::new(opn)
                .args(["file", "/dev/null", "--json"])
                .output()
                .expect("failed to run opn");
            black_box(output.stdout);
        });
    });

    if Command::new("lsof").arg("-v").output().is_ok() {
        group.bench_function("lsof /dev/null", |b| {
            b.iter(|| {
                let output = Command::new("lsof")
                    .args(["/dev/null"])
                    .output()
                    .expect("failed to run lsof");
                black_box(output.stdout);
            });
        });
    }

    group.finish();
}

fn bench_json_serialization(c: &mut Criterion) {
    let opn = env!("CARGO_BIN_EXE_opn");

    let mut group = c.benchmark_group("json_vs_table");

    group.bench_function("sockets --json", |b| {
        b.iter(|| {
            let output = Command::new(opn)
                .args(["sockets", "--json"])
                .output()
                .expect("failed to run opn");
            black_box(output.stdout);
        });
    });

    group.bench_function("sockets (table)", |b| {
        b.iter(|| {
            let output = Command::new(opn)
                .args(["sockets"])
                .output()
                .expect("failed to run opn");
            black_box(output.stdout);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_opn_sockets,
    bench_opn_port,
    bench_opn_pid,
    bench_opn_file,
    bench_json_serialization,
);
criterion_main!(benches);
