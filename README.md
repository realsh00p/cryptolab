# cryptolab

A polyglot workspace for Python 3.12, stable Rust, and C++26 with Clang.

> [!WARNING]
> This project is strictly a personal learning experiment, built for exploration
> and peace of mind. It is not intended, reviewed, or suitable for production use.
> Do not use its cryptographic implementations to protect real data, credentials,
> communications, or systems.

## Layout

```text
py/                         Python distribution
  src/cryptolab/            Importable package
rs/                         Cargo workspace
  cryptolab/                Rust RSA executable
cpp/                        CMake project
  cryptolab/                C++ RSA library and executable
```

Open the repository in its VS Code dev container before running these commands.
The container provides Python 3.12, Rust, Clang, CMake, GMP, and OpenSSL. For the
committed editor configuration, open `cryptolab.code-workspace` in VS Code.

## Python

Python does not require a compilation step. Create its virtual environment and
install the package and its dependencies in editable mode:

```bash
python -m venv py/.venv
py/.venv/bin/python -m pip install --editable './py[dev]'
```

Run it with:

```bash
py/.venv/bin/python -m cryptolab
```

Format and lint it with Ruff:

```bash
py/.venv/bin/ruff format py
py/.venv/bin/ruff check py
```

## Rust

Build the optimized executable:

```bash
cargo build --release --manifest-path rs/Cargo.toml -p cryptolab
```

Run it with:

```bash
./rs/target/release/cryptolab
```

## C++

Configure and build the project using the Clang C++26 preset:

```bash
cmake --preset dev -S cpp
cmake --build cpp/build
```

Run it with:

```bash
./cpp/build/cryptolab/cryptolab_cpp
```

The CMake preset emits `cpp/build/compile_commands.json`, which clangd uses for
diagnostics, navigation, and background indexing.

## Build and run everything

From anywhere inside the devcontainer, use the root-level helper script to set up
Python, build the optimized Rust executable and C++ executable, and then run all
three implementations in sequence:

```bash
./build-and-run.sh
```

The script reuses the existing Python virtual environment and build directories.
To remove the Python virtual environment, Rust target directory, and CMake build
directory before rebuilding everything, pass `--clean`:

```bash
./build-and-run.sh --clean
```
