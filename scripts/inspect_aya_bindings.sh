#!/usr/bin/env bash
set -euo pipefail

root="${HOME}/.cargo/registry/src"

crate_dir="$(
  find "$root" -maxdepth 2 -type d -name 'aya-ebpf-bindings-*' | head -n 1
)"

if [[ -z "${crate_dir}" ]]; then
  echo "aya-ebpf-bindings crate not found under ${root}" >&2
  exit 1
fi

echo "crate: ${crate_dir}"
echo
echo "public exports:"
if command -v rg >/dev/null 2>&1; then
  rg -n "pub use|pub mod" "${crate_dir}/src" -g '*.rs' || true
else
  grep -RniE "pub use|pub mod" "${crate_dir}/src" --include='*.rs' || true
fi
echo
echo "sock-like symbols:"
if command -v rg >/dev/null 2>&1; then
  rg -n "sock|sock_common|skc_" "${crate_dir}/src" -g '*.rs' || true
else
  grep -RniE "sock|sock_common|skc_" "${crate_dir}/src" --include='*.rs' || true
fi
