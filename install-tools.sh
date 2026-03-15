#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*"; }

ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

# Normalise arch names to match GitHub release naming
case "$ARCH" in
    x86_64)  ARCH_GO="amd64" ;;
    aarch64|arm64) ARCH_GO="arm64" ;;
    *) ARCH_GO="$ARCH" ;;
esac

# Ensure ~/go/bin and ~/.pdtm/go/bin are in PATH for this session
export PATH="$HOME/go/bin:$HOME/.pdtm/go/bin:$HOME/.local/bin:$PATH"

# ─── Helper: install via go install ──────────────────────────────────
install_go_tool() {
    local name="$1" pkg="$2" env="${3:-}"
    if command -v "$name" &>/dev/null; then
        warn "$name is already installed at $(command -v "$name")"
        return
    fi
    info "Installing $name via go install..."
    if [[ -n "$env" ]]; then
        env $env go install -v "$pkg"
    else
        go install -v "$pkg"
    fi
    if command -v "$name" &>/dev/null; then
        info "$name installed successfully."
    else
        error "$name binary not found after go install. Check that ~/go/bin is in your PATH."
    fi
}

# ─── Helper: install from GitHub release tarball ─────────────────────
install_from_github() {
    local name="$1" repo="$2" url_pattern="$3"
    if command -v "$name" &>/dev/null; then
        warn "$name is already installed at $(command -v "$name")"
        return
    fi
    info "Installing $name from GitHub release..."

    local latest_tag
    latest_tag=$(curl -sI "https://github.com/${repo}/releases/latest" \
        | grep -i '^location:' | sed 's|.*/||' | tr -d '\r\n')

    if [[ -z "$latest_tag" ]]; then
        error "Could not determine latest release for $repo"
        return 1
    fi

    # Build download URL from pattern (replace {tag}, {version}, {os}, {arch})
    local version="${latest_tag#v}"
    local url="$url_pattern"
    url="${url//\{tag\}/$latest_tag}"
    url="${url//\{version\}/$version}"
    url="${url//\{os\}/$OS}"
    url="${url//\{arch\}/$ARCH_GO}"

    local tmpdir
    tmpdir=$(mktemp -d)
    trap "rm -rf '$tmpdir'" RETURN

    info "Downloading $url"
    if ! curl -sL "$url" -o "$tmpdir/archive.zip"; then
        error "Failed to download $name"
        return 1
    fi

    # Extract - handle both .zip and .tar.gz
    if [[ "$url" == *.zip ]]; then
        unzip -qo "$tmpdir/archive.zip" -d "$tmpdir"
    else
        tar xzf "$tmpdir/archive.zip" -C "$tmpdir"
    fi

    # Move binary to ~/go/bin (create if needed)
    mkdir -p "$HOME/go/bin"
    if [[ -f "$tmpdir/$name" ]]; then
        mv "$tmpdir/$name" "$HOME/go/bin/$name"
        chmod +x "$HOME/go/bin/$name"
        info "$name installed to ~/go/bin/$name"
    else
        error "Could not find $name binary in extracted archive"
        return 1
    fi
}

# ─── Check prerequisites ─────────────────────────────────────────────
HAS_GO=false
if command -v go &>/dev/null; then
    HAS_GO=true
    info "Go found: $(go version)"
else
    warn "Go not found. Will attempt to install tools from GitHub releases."
    warn "For best results, install Go from https://go.dev/dl/"
fi

# ─── ProjectDiscovery tools ──────────────────────────────────────────
if $HAS_GO; then
    install_go_tool subfinder       "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool httpx           "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    install_go_tool nuclei          "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    install_go_tool katana          "github.com/projectdiscovery/katana/cmd/katana@latest" "CGO_ENABLED=1"
    install_go_tool interactsh-client "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    install_go_tool ffuf            "github.com/ffuf/ffuf/v2@latest"
    install_go_tool dalfox          "github.com/hahwul/dalfox/v2@latest"
else
    # Fallback: download pre-built binaries from GitHub releases
    install_from_github subfinder "projectdiscovery/subfinder" \
        "https://github.com/projectdiscovery/subfinder/releases/download/{tag}/subfinder_{version}_{os}_{arch}.zip"
    install_from_github httpx "projectdiscovery/httpx" \
        "https://github.com/projectdiscovery/httpx/releases/download/{tag}/httpx_{version}_{os}_{arch}.zip"
    install_from_github nuclei "projectdiscovery/nuclei" \
        "https://github.com/projectdiscovery/nuclei/releases/download/{tag}/nuclei_{version}_{os}_{arch}.zip"
    install_from_github katana "projectdiscovery/katana" \
        "https://github.com/projectdiscovery/katana/releases/download/{tag}/katana_{version}_{os}_{arch}.zip"
    install_from_github interactsh-client "projectdiscovery/interactsh" \
        "https://github.com/projectdiscovery/interactsh/releases/download/{tag}/interactsh-client_{version}_{os}_{arch}.zip"
    install_from_github ffuf "ffuf/ffuf" \
        "https://github.com/ffuf/ffuf/releases/download/{tag}/ffuf_{version}_{os}_{arch}.tar.gz"
    install_from_github dalfox "hahwul/dalfox" \
        "https://github.com/hahwul/dalfox/releases/download/{tag}/dalfox_{version}_{os}_{arch}.tar.gz"
fi

# ─── nmap (system package) ───────────────────────────────────────────
if command -v nmap &>/dev/null; then
    warn "nmap is already installed at $(command -v nmap)"
else
    info "Installing nmap..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get update && sudo apt-get install -y nmap
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y nmap
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm nmap
    elif command -v brew &>/dev/null; then
        brew install nmap
    else
        error "Could not detect package manager. Install nmap manually: https://nmap.org/download"
    fi
fi

# ─── wafw00f (Python) ────────────────────────────────────────────────
if command -v wafw00f &>/dev/null; then
    warn "wafw00f is already installed at $(command -v wafw00f)"
else
    info "Installing wafw00f..."
    if command -v pipx &>/dev/null; then
        pipx install wafw00f
    elif command -v pip3 &>/dev/null; then
        pip3 install wafw00f
    else
        error "pip3 or pipx is required to install wafw00f."
    fi
fi

# ─── arjun (Python) ─────────────────────────────────────────────────
if command -v arjun &>/dev/null; then
    warn "arjun is already installed at $(command -v arjun)"
else
    info "Installing arjun..."
    if command -v pipx &>/dev/null; then
        pipx install arjun
    elif command -v pip3 &>/dev/null; then
        pip3 install arjun
    else
        error "pip3 or pipx is required to install arjun."
    fi
fi

# ─── sqlmap (git clone) ─────────────────────────────────────────────
if command -v sqlmap &>/dev/null; then
    warn "sqlmap is already installed at $(command -v sqlmap)"
else
    info "Installing sqlmap..."
    SQLMAP_DIR="$HOME/.local/share/sqlmap"
    SQLMAP_BIN="$HOME/.local/bin/sqlmap"
    if [[ -d "$SQLMAP_DIR" ]]; then
        info "Updating existing sqlmap clone..."
        git -C "$SQLMAP_DIR" pull --quiet
    else
        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$SQLMAP_DIR"
    fi
    mkdir -p "$HOME/.local/bin"
    cat > "$SQLMAP_BIN" << 'WRAPPER'
#!/usr/bin/env bash
exec python3 "$HOME/.local/share/sqlmap/sqlmap.py" "$@"
WRAPPER
    chmod +x "$SQLMAP_BIN"
    if command -v sqlmap &>/dev/null; then
        info "sqlmap installed successfully."
    else
        warn "sqlmap installed to $SQLMAP_BIN — ensure ~/.local/bin is in your PATH."
    fi
fi

# ─── Verification ────────────────────────────────────────────────────
echo ""
info "Verifying installations..."
echo ""

tools=(subfinder httpx nuclei katana interactsh-client ffuf dalfox nmap wafw00f arjun sqlmap)
all_ok=true
for tool in "${tools[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $tool  ($(command -v "$tool"))"
    else
        echo -e "  ${RED}✗${NC} $tool  (not found in PATH)"
        all_ok=false
    fi
done

echo ""
if $all_ok; then
    info "All tools installed successfully!"
else
    warn "Some tools are missing. Make sure ~/go/bin is in your PATH:"
    echo '  export PATH="$HOME/go/bin:$PATH"'
    echo ""
    warn "Add the line above to your ~/.bashrc or ~/.zshrc to make it permanent."
fi
