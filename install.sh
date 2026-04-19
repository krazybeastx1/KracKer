#!/bin/bash
set -e

echo "========================================"
echo "       KracKer Installer v1.0           "
echo "========================================"
echo ""

# Detect OS
OS="$(uname -s)"
echo "[*] Detected OS: $OS"

# Install dependencies
case "$OS" in
    Darwin)
        echo "[*] Installing macOS dependencies..."
        if ! command -v brew &> /dev/null; then
            echo "[!] Homebrew not found. Install it first:"
            echo "    /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
            exit 1
        fi
        brew install cmake openssl
        ;;
    Linux)
        if [ -f /etc/debian_version ]; then
            echo "[*] Installing Debian/Ubuntu dependencies..."
            sudo apt update
            sudo apt install -y cmake libssl-dev g++
        elif [ -f /etc/redhat-release ]; then
            echo "[*] Installing RHEL/CentOS dependencies..."
            sudo dnf install -y cmake openssl-devel gcc-c++
        elif [ -f /etc/arch-release ]; then
            echo "[*] Installing Arch dependencies..."
            sudo pacman -Sy --noconfirm cmake openssl gcc
        else
            echo "[!] Unknown Linux distro. Install cmake, OpenSSL, g++ manually."
            exit 1
        fi
        ;;
    *)
        echo "[!] Unsupported OS: $OS"
        exit 1
        ;;
esac

# Build
echo ""
echo "[*] Building KracKer..."
mkdir -p build
cd build
cmake ..
make

echo ""
echo "========================================"
echo "[+] Build complete!"
echo "    Binary: ./build/KracKer"
echo "========================================"
echo ""
echo "[*] Installing to /usr/local/bin..."
sudo cp ./build/KracKer /usr/local/bin/
sudo ln -sf /usr/local/bin/KracKer /usr/local/bin/kracker
echo ""
echo "Quick start:"
echo "  kracker -h 5f4dcc3b5aa765d61d8327deb882cf99 -w rockyou.txt"
echo "  kracker --help"
