#!/usr/bin/env bash
# KracKer v2 installer / build helper.
#
# Builds the CPU cracker with CMake and (optionally) installs it. GPU and
# distributed backends are experimental and off by default; see README.md.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              KracKer v2.0.0 Installer                       ║"
    echo "║        CPU hash cracker with session resume                 ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step()    { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error()   { echo -e "${RED}[-]${NC} $1"; }

# Defaults
INSTALL_PREFIX="/usr/local"
BUILD_TYPE="Release"
BUILD_DIR="build"
RUN_TESTS=OFF
DO_INSTALL=ON
CLEAN_BUILD=OFF
JOBS="$( (nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2) )"

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
    --prefix PATH       Installation prefix (default: /usr/local)
    --build-type TYPE   Debug, Release, RelWithDebInfo (default: Release)
    --build-dir DIR     Build directory (default: build)
    --jobs N            Parallel build jobs (default: number of CPUs)
    --run-tests         Build and run unit tests (requires GTest)
    --no-install        Build only, do not install
    --clean             Remove the build directory first
    --help              Show this help

Examples:
    $0                                  # build + install to /usr/local
    $0 --prefix ~/.local --no-install   # build into ./build, no install
    $0 --clean --run-tests              # clean rebuild with tests

Build options are passed straight through to CMake, e.g.:
    cmake -S . -B build -DWITH_OPENCL=ON   # experimental GPU backend
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --prefix)     INSTALL_PREFIX="$2"; shift 2 ;;
            --build-type) BUILD_TYPE="$2"; shift 2 ;;
            --build-dir)  BUILD_DIR="$2"; shift 2 ;;
            --jobs)       JOBS="$2"; shift 2 ;;
            --run-tests)  RUN_TESTS=ON; shift ;;
            --no-install) DO_INSTALL=OFF; shift ;;
            --clean)      CLEAN_BUILD=ON; shift ;;
            --help)       usage; exit 0 ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Prints the package name to install for a given dependency (informational).
check_dependencies() {
    print_step "Checking dependencies..."

    local missing=()

    command -v cmake >/dev/null 2>&1 || missing+=("cmake")

    if ! command -v g++ >/dev/null 2>&1 && ! command -v clang++ >/dev/null 2>&1; then
        missing+=("g++")
    fi

    # OpenSSL headers (libssl-dev)
    if ! pkg-config --exists openssl 2>/dev/null; then
        if [[ ! -f /usr/include/openssl/evp.h ]]; then
            missing+=("libssl-dev")
        fi
    fi

    # nlohmann/json headers
    if ! find /usr/include /usr/local/include -maxdepth 3 \
            -path '*/nlohmann/json.hpp' -print -quit 2>/dev/null | grep -q .; then
        missing+=("nlohmann-json3-dev")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        print_error "Missing required dependency: ${missing[*]}"
        echo
        if command -v apt >/dev/null 2>&1; then
            echo "  sudo apt update && sudo apt install -y ${missing[*]}"
        elif command -v pacman >/dev/null 2>&1; then
            echo "  sudo pacman -S --needed base-devel cmake openssl nlohmann-json"
        elif command -v dnf >/dev/null 2>&1; then
            echo "  sudo dnf install gcc-c++ cmake openssl-devel nlohmann-json-devel"
        elif command -v brew >/dev/null 2>&1; then
            echo "  brew install cmake openssl nlohmann-json"
        fi
        exit 1
    fi

    # libcrypt provides the reentrant crypt_rn()/crypt_gensalt_rn() used by
    # bcrypt. Only the runtime library is required (no headers).
    if ! ldconfig -p 2>/dev/null | grep -q 'libcrypt\.so'; then
        print_warning "libcrypt not found - bcrypt support will be disabled"
    fi

    # Optional: OpenCL / CUDA / GTest
    if ! command -v pkg-config >/dev/null 2>&1; then
        print_warning "pkg-config not found; relying on CMake's own detection"
    fi

    if [[ $RUN_TESTS == ON ]]; then
        if ! (cmake --find-package -DNAME=GTest -DCOMPILER_ID=GNU \
                -DLANGUAGE=CXX -DMODE=EXIST >/dev/null 2>&1); then
            print_warning "GTest not detected - tests will be skipped by CMake"
            print_warning "Install it with: sudo apt install libgtest-dev"
        fi
    fi

    print_step "Dependencies satisfied"
}

build_project() {
    print_step "Configuring ($BUILD_TYPE)..."

    if [[ $CLEAN_BUILD == ON && -d "$BUILD_DIR" ]]; then
        print_step "Removing $BUILD_DIR..."
        rm -rf "$BUILD_DIR"
    fi

    cmake -S . -B "$BUILD_DIR" \
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
        -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
        -DBUILD_TESTS="$RUN_TESTS"

    print_step "Building with $JOBS job(s)..."
    cmake --build "$BUILD_DIR" -j "$JOBS"
}

run_tests() {
    [[ $RUN_TESTS == ON ]] || return 0

    print_step "Running tests..."
    if ! ctest --test-dir "$BUILD_DIR" --output-on-failure; then
        print_error "Tests failed"
        exit 1
    fi
}

install_project() {
    [[ $DO_INSTALL == ON ]] || { print_step "Skipping install (--no-install)"; return 0; }

    print_step "Installing to $INSTALL_PREFIX..."

    # Only ask for sudo when the prefix is not writable by the current user.
    if [[ -w "$INSTALL_PREFIX" || -w "$(dirname "$INSTALL_PREFIX")" ]]; then
        cmake --install "$BUILD_DIR" --prefix "$INSTALL_PREFIX"
    else
        sudo cmake --install "$BUILD_DIR" --prefix "$INSTALL_PREFIX"
    fi

    if [[ "$(uname -s)" == "Linux" ]]; then
        sudo ldconfig 2>/dev/null || true
    fi
}

verify_installation() {
    local bin="$BUILD_DIR/bin/KracKer"
    [[ $DO_INSTALL == ON ]] && bin="$INSTALL_PREFIX/bin/KracKer"

    print_step "Verifying $bin ..."
    if [[ ! -x "$bin" ]]; then
        print_error "Binary not found at $bin"
        exit 1
    fi

    "$bin" --list-hashes | sed -n '/Supported Hash Types/,$p'
}

main() {
    parse_args "$@"
    print_banner

    echo "Configuration:"
    echo "  Prefix:      $INSTALL_PREFIX"
    echo "  Build type:  $BUILD_TYPE"
    echo "  Build dir:   $BUILD_DIR"
    echo "  Jobs:        $JOBS"
    echo "  Tests:       $RUN_TESTS"
    echo "  Install:     $DO_INSTALL"
    echo "  Clean build: $CLEAN_BUILD"
    echo ""

    check_dependencies
    build_project
    run_tests
    install_project
    verify_installation

    echo ""
    print_step "Done."
    echo
    echo "Quick start:"
    echo "  KracKer -t md5 -h 5f4dcc3b5aa765d61d8327deb882cf99 -w /usr/share/wordlists/rockyou.txt"
    echo "  KracKer -h <hash> -a mask -m '?u?l?l?l?l?d?d'"
    echo "  KracKer -h <ntlm> -t ntlm -w rockyou.txt -s session.json"
    echo "  KracKer --identify -h <hash>"
    echo
    echo "Note: GPU (OpenCL/CUDA) and distributed master/worker modes are"
    echo "      experimental and disabled in this build. See README.md."
}

main "$@"
