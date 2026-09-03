#!/bin/sh
# PatchFlow CLI install script
# Usage: curl -fsSL https://github.com/Patchflow-security/patchflow-cli/raw/main/scripts/install.sh | bash
#   or: curl -fsSL https://github.com/Patchflow-security/patchflow-cli/raw/main/scripts/install.sh | bash -s -- --version v0.1.6
set -eu

# --- defaults ---
VERSION="latest"
INSTALL_DIR="${INSTALL_DIR:-${HOME}/.local/bin}"
REPO="Patchflow-security/patchflow-cli"
NO_VERIFY="${NO_VERIFY:-0}"

# --- helpers ---
out() { printf '%s\n' "$*"; }
err() { printf '%s\n' "$*" >&2; }

# --- parse args ---
while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            if [ $# -lt 2 ]; then
                err "--version requires a value"
                exit 1
            fi
            VERSION="$2"
            shift 2
            ;;
        --install-dir)
            if [ $# -lt 2 ]; then
                err "--install-dir requires a value"
                exit 1
            fi
            INSTALL_DIR="$2"
            shift 2
            ;;
        --no-verify)
            NO_VERIFY=1
            shift
            ;;
        --help)
            out "Install the PatchFlow CLI on Linux or macOS."
            out ""
            out "Usage:"
            out "  curl -fsSL https://github.com/Patchflow-security/patchflow-cli/raw/main/scripts/install.sh | bash"
            out "  curl -fsSL https://github.com/Patchflow-security/patchflow-cli/raw/main/scripts/install.sh | bash -s -- --version vX.Y.Z"
            out "  curl -fsSL https://github.com/Patchflow-security/patchflow-cli/raw/main/scripts/install.sh | bash -s -- --install-dir /usr/local/bin"
            out ""
            out "Options:"
            out "  --version <tag>      Install a specific release (default: latest)"
            out "  --install-dir <dir>  Install into this directory (default: \$HOME/.local/bin)"
            out "  --no-verify          Skip running the binary after installation"
            out "  --help               Show this help message"
            out ""
            out "Environment variables:"
            out "  INSTALL_DIR          Same as --install-dir"
            out "  NO_VERIFY=1          Same as --no-verify"
            exit 0
            ;;
        *)
            err "Unknown option: $1"
            out "Run with --help for usage."
            exit 1
            ;;
    esac
done

# --- detect platform ---
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Darwin) OS="macos" ;;
    Linux)  OS="linux" ;;
    *)
        err "Unsupported OS: $OS"
        err "PatchFlow CLI supports Linux and macOS."
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *)
        err "Unsupported architecture: $ARCH"
        err "PatchFlow CLI supports x86_64 and arm64."
        exit 1
        ;;
esac

# --- resolve version ---
if [ "$VERSION" = "latest" ]; then
    out "Fetching latest release version..."
    VERSION=$(curl --proto '=https' --tlsv1.2 -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -z "$VERSION" ]; then
        err "Failed to determine latest version."
        err "Specify explicitly: --version v0.1.0"
        exit 1
    fi
fi

# Strip leading 'v' for URL construction (GitHub releases use it, download URLs may not)
VERSION_NUM="${VERSION#v}"

# --- construct download URL ---
# goreleaser archive naming: patchflow_VERSION_OS_ARCH.tar.gz
ARCHIVE="patchflow_${VERSION_NUM}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"

out "Downloading PatchFlow CLI ${VERSION} for ${OS}/${ARCH}..."
out "  ${URL}"

# --- download ---
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

if ! curl --proto '=https' --tlsv1.2 -fsSL -o "${TMPDIR}/${ARCHIVE}" "$URL"; then
    err "Download failed. Check that version ${VERSION} exists."
    exit 1
fi

# --- verify checksum ---
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
if ! curl --proto '=https' --tlsv1.2 -fsSL -o "${TMPDIR}/checksums.txt" "$CHECKSUM_URL"; then
    err "Checksum file not found; refusing to install an unverified archive."
    exit 1
fi

out "Verifying checksum..."
if ! awk -v archive="$ARCHIVE" '$2 == archive { print; found = 1 } END { exit found ? 0 : 1 }' "${TMPDIR}/checksums.txt" > "${TMPDIR}/checksum.expected"; then
    err "Checksum entry for ${ARCHIVE} not found."
    exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$TMPDIR" && sha256sum -c checksum.expected) || {
        err "Checksum verification failed!"
        exit 1
    }
else
    (cd "$TMPDIR" && shasum -a 256 -c checksum.expected) || {
        err "Checksum verification failed!"
        exit 1
    }
fi

# Verify the signed checksum when cosign is available. Checksum verification is
# still mandatory above so installs work on hosts without cosign.
if command -v cosign >/dev/null 2>&1; then
    SIG_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt.sig"
    CERT_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt.pem"
    if curl --proto '=https' --tlsv1.2 -fsSL -o "${TMPDIR}/checksums.txt.sig" "$SIG_URL" &&
       curl --proto '=https' --tlsv1.2 -fsSL -o "${TMPDIR}/checksums.txt.pem" "$CERT_URL"; then
        out "Verifying checksum signature..."
        cosign verify-blob \
            --certificate "${TMPDIR}/checksums.txt.pem" \
            --signature "${TMPDIR}/checksums.txt.sig" \
            --certificate-identity "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${VERSION}" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            "${TMPDIR}/checksums.txt" >/dev/null || {
                err "Cosign signature verification failed."
                exit 1
            }
    else
        err "Warning: checksum signature files not found; checksum verification completed without signature verification."
    fi
fi

# --- extract ---
out "Extracting..."
if ! tar -tzf "${TMPDIR}/${ARCHIVE}" | awk '
    /^\/|(^|\/)\.\.($|\/)/ {
        print "Unsafe archive path: " $0 > "/dev/stderr"
        bad = 1
    }
    END { exit bad ? 1 : 0 }
'; then
    err "Archive contains unsafe paths; refusing to extract."
    exit 1
fi
tar -xzf "${TMPDIR}/${ARCHIVE}" -C "$TMPDIR"

# --- install ---
mkdir -p "$INSTALL_DIR"
if [ ! -f "${TMPDIR}/patchflow" ]; then
    err "Archive did not contain the patchflow binary."
    exit 1
fi
if ! install -m 0755 "${TMPDIR}/patchflow" "${INSTALL_DIR}/patchflow" 2>/dev/null; then
    cp "${TMPDIR}/patchflow" "${INSTALL_DIR}/patchflow"
    chmod 0755 "${INSTALL_DIR}/patchflow"
fi

out ""
out "Installed PatchFlow CLI ${VERSION} to ${INSTALL_DIR}/patchflow"

# --- verify installation ---
if [ "$NO_VERIFY" -eq 0 ]; then
    out ""
    out "Verifying installation..."
    VERSION_OUTPUT="${TMPDIR}/patchflow-version.txt"
    if "${INSTALL_DIR}/patchflow" version >"${VERSION_OUTPUT}" 2>&1; then
        out "Installation verified."
        cat "${VERSION_OUTPUT}"
    else
        err "Installation verification failed. The binary was installed but does not run correctly."
        cat "${VERSION_OUTPUT}" >&2
        exit 1
    fi
fi

# --- PATH instructions ---
# This script cannot modify the parent shell's PATH when piped via curl | bash.
# We provide exact commands the user can copy-paste.
case ":${PATH}:" in
    *":${INSTALL_DIR}:"*)
        out ""
        out "${INSTALL_DIR} is already in your PATH. You can run 'patchflow' now."
        ;;
    *)
        out ""
        out "patchflow is installed, but ${INSTALL_DIR} is NOT in your PATH."
        out ""
        out "To use patchflow in the current terminal, run:"
        out "  export PATH=\"${INSTALL_DIR}:\$PATH\""
        out ""
        out "To make this permanent, add the same line to your shell profile:"
        if [ -f "${HOME}/.zshrc" ] && [ -f "${HOME}/.bashrc" ]; then
            out "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.bashrc"
            out "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.zshrc"
        elif [ -f "${HOME}/.zshrc" ]; then
            out "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.zshrc"
        elif [ -f "${HOME}/.bashrc" ]; then
            out "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.bashrc"
        else
            out "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.profile"
        fi
        ;;
esac

out ""
out "Get started: patchflow version"
