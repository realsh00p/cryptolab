FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RUSTUP_HOME=/opt/rust/rustup \
    CARGO_HOME=/opt/rust/cargo \
    PATH=/opt/rust/cargo/bin:$PATH

ARG LLVM_VERSION=22
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        curl \
        git \
        gnupg \
        lsb-release \
        libgmp-dev \
        libssl-dev \
        m4 \
        ninja-build \
        openssh-client \
        sudo \
        wget \
        vim \
    && wget --quiet https://apt.llvm.org/llvm.sh \
    && chmod +x llvm.sh \
    && ./llvm.sh "${LLVM_VERSION}" \
    && apt-get install --yes --no-install-recommends \
        "clang-format-${LLVM_VERSION}" \
        "clang-tidy-${LLVM_VERSION}" \
        "clang-tools-${LLVM_VERSION}" \
        "clangd-${LLVM_VERSION}" \
        "libc++-${LLVM_VERSION}-dev" \
        "libc++abi-${LLVM_VERSION}-dev" \
        "lld-${LLVM_VERSION}" \
    && update-alternatives --install /usr/bin/clang clang "/usr/bin/clang-${LLVM_VERSION}" 220 \
    && update-alternatives --install /usr/bin/clang++ clang++ "/usr/bin/clang++-${LLVM_VERSION}" 220 \
    && update-alternatives --install /usr/bin/clangd clangd "/usr/bin/clangd-${LLVM_VERSION}" 220 \
    && update-alternatives --install /usr/bin/clang-format clang-format "/usr/bin/clang-format-${LLVM_VERSION}" 220 \
    && update-alternatives --install /usr/bin/clang-tidy clang-tidy "/usr/bin/clang-tidy-${LLVM_VERSION}" 220 \
    && update-alternatives --install /usr/bin/lld lld "/usr/bin/lld-${LLVM_VERSION}" 220 \
    && rm -f llvm.sh \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p "${RUSTUP_HOME}" "${CARGO_HOME}" \
    && curl --proto '=https' --tlsv1.2 --silent --show-error --fail https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --profile minimal --component clippy,rust-analyzer,rustfmt --no-modify-path \
    && chmod -R a+rwX "${RUSTUP_HOME}" "${CARGO_HOME}"

RUN groupadd --gid 1000 vscode \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash vscode \
    && usermod --append --groups sudo vscode

COPY --chmod=0440 .devcontainer/sudoers-vscode /etc/sudoers.d/vscode

WORKDIR /workspaces/cryptolab

USER vscode
