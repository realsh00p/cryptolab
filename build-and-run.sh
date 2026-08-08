#!/usr/bin/env bash

set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
clean=false

case "${1:-}" in
    "")
        ;;
    --clean)
        clean=true
        ;;
    *)
        echo "Usage: $0 [--clean]" >&2
        exit 2
        ;;
esac

if (( $# > 1 )); then
    echo "Usage: $0 [--clean]" >&2
    exit 2
fi

if [[ "${clean}" == true ]]; then
    echo "Removing generated environments, build directories, and caches..."
    rm -rf -- \
        "${project_root}/py/.venv" \
        "${project_root}/rs/target" \
        "${project_root}/cpp/build"
fi

echo "Building Python project..."
if [[ ! -x "${project_root}/py/.venv/bin/python" ]]; then
    python -m venv "${project_root}/py/.venv"
fi
"${project_root}/py/.venv/bin/python" -m pip install --editable "${project_root}/py[dev]"

echo "Building Rust project..."
cargo build --release --manifest-path "${project_root}/rs/Cargo.toml" -p cryptolab

echo "Building C++ project..."
cmake --preset dev -S "${project_root}/cpp"
cmake --build "${project_root}/cpp/build"

echo "Running Python implementation..."
"${project_root}/py/.venv/bin/python" -m cryptolab

echo "Running Rust implementation..."
"${project_root}/rs/target/release/cryptolab"

echo "Running C++ implementation..."
"${project_root}/cpp/build/cryptolab/cryptolab_cpp"
