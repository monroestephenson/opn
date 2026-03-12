use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=OPN_EBPF_BUNDLE_SOURCE");
    println!("cargo:rerun-if-env-changed=OPN_EBPF_SKIP_BUNDLE");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let ebpf_enabled = env::var_os("CARGO_FEATURE_EBPF").is_some();
    if target_os != "linux" || !ebpf_enabled {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bundle_rs = out_dir.join("ebpf_bundle.rs");

    if env::var_os("OPN_EBPF_SKIP_BUNDLE").is_some() {
        write_bundle_source(&bundle_rs, None);
        return;
    }

    let source = env::var_os("OPN_EBPF_BUNDLE_SOURCE")
        .map(PathBuf::from)
        .or_else(|| discover_ebpf_object(&manifest_dir));

    let Some(source) = source else {
        write_bundle_source(&bundle_rs, None);
        return;
    };

    println!("cargo:rerun-if-changed={}", source.display());
    write_bundle_source(&bundle_rs, Some(&source));
}

fn discover_ebpf_object(repo_root: &Path) -> Option<PathBuf> {
    [
        repo_root.join("target/bpfel-unknown-none/release/opn-ebpf"),
        repo_root.join("target/bpfel-unknown-none/debug/opn-ebpf"),
        repo_root.join("target/bpfel-unknown-none/release/opn-ebpf.o"),
        repo_root.join("target/bpfel-unknown-none/debug/opn-ebpf.o"),
        repo_root.join("ebpf/target/bpfel-unknown-none/release/opn-ebpf"),
        repo_root.join("ebpf/target/bpfel-unknown-none/debug/opn-ebpf"),
        repo_root.join("ebpf/target/bpfel-unknown-none/release/opn-ebpf.o"),
        repo_root.join("ebpf/target/bpfel-unknown-none/debug/opn-ebpf.o"),
    ]
    .into_iter()
    .find(|path| path.exists())
}

fn write_bundle_source(path: &Path, source: Option<&Path>) {
    let content = match source.and_then(|source| fs::read(source).ok()) {
        Some(bytes) => {
            let len = bytes.len();
            let byte_str = bytes
                .iter()
                .map(|byte| byte.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "pub static BUNDLED_EBPF_BYTES: [u8; {len}] = [{byte_str}];\n\
                 pub const BUNDLED_EBPF_OBJECT: Option<&'static [u8]> = Some(&BUNDLED_EBPF_BYTES);\n",
            )
        }
        None => String::from("pub const BUNDLED_EBPF_OBJECT: Option<&'static [u8]> = None;\n"),
    };
    let _ = fs::write(path, content);
}
