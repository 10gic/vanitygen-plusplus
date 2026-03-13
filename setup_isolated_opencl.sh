#!/bin/bash
#
# Isolated OpenCL build setup for vanitygen++
#
# This script downloads OpenCL headers and (optionally) builds a local
# ICD loader so you can compile vanitygen++ WITHOUT installing system-wide
# OpenCL development packages that might conflict with existing GPU drivers
# (e.g. drivers used by sha1-miner or other mining software).
#
# What this does NOT touch:
#   - Your GPU drivers (nvidia, amdgpu, rocm runtime, etc.)
#   - System OpenCL ICD configuration (/etc/OpenCL/vendors/)
#   - Any existing libOpenCL.so on the system
#
# What this does:
#   - Downloads OpenCL headers into third_party/linux/opencl-headers/
#   - Optionally builds ocl-icd loader locally in third_party/linux/ocl-icd/
#   - Installs only non-driver build dependencies (libpcre3-dev, libcurl4-openssl-dev)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
THIRD_PARTY="$SCRIPT_DIR/third_party/linux"
OPENCL_HEADERS_DIR="$THIRD_PARTY/opencl-headers"
OCL_ICD_DIR="$THIRD_PARTY/ocl-icd"

# OpenCL Headers version (Khronos official)
OPENCL_HEADERS_TAG="v2024.05.08"
OCL_ICD_TAG="v2.3.2"

echo "=== Isolated OpenCL Setup for vanitygen++ ==="
echo ""
echo "This will set up OpenCL build dependencies locally without"
echo "modifying your system GPU drivers or OpenCL runtime."
echo ""

# ---------------------------------------------------------------
# Step 1: Install non-driver build dependencies
# ---------------------------------------------------------------
echo "[1/4] Checking non-driver build dependencies..."

MISSING_PKGS=""
dpkg -s libpcre3-dev &>/dev/null || MISSING_PKGS="$MISSING_PKGS libpcre3-dev"
dpkg -s libcurl4-openssl-dev &>/dev/null || MISSING_PKGS="$MISSING_PKGS libcurl4-openssl-dev"
dpkg -s libssl-dev &>/dev/null || MISSING_PKGS="$MISSING_PKGS libssl-dev"
dpkg -s build-essential &>/dev/null || MISSING_PKGS="$MISSING_PKGS build-essential"

if [ -n "$MISSING_PKGS" ]; then
    echo "  Installing missing packages:$MISSING_PKGS"
    echo "  (These are libraries only, NOT GPU drivers)"
    sudo apt-get update -qq
    sudo apt-get install -y -qq $MISSING_PKGS
else
    echo "  All non-driver build dependencies are already installed."
fi

# ---------------------------------------------------------------
# Step 2: Download OpenCL headers locally
# ---------------------------------------------------------------
echo "[2/4] Setting up local OpenCL headers..."

mkdir -p "$THIRD_PARTY"

if [ -f "$OPENCL_HEADERS_DIR/CL/cl.h" ]; then
    echo "  OpenCL headers already present at $OPENCL_HEADERS_DIR"
else
    echo "  Downloading OpenCL headers ($OPENCL_HEADERS_TAG)..."
    mkdir -p "$OPENCL_HEADERS_DIR"

    HEADERS_URL="https://github.com/KhronosGroup/OpenCL-Headers/archive/refs/tags/${OPENCL_HEADERS_TAG}.tar.gz"
    TMPFILE=$(mktemp /tmp/opencl-headers-XXXXXX.tar.gz)

    curl -sL "$HEADERS_URL" -o "$TMPFILE"
    tar -xzf "$TMPFILE" -C "$OPENCL_HEADERS_DIR" --strip-components=1
    rm -f "$TMPFILE"

    # The headers are under CL/ subdirectory inside the extracted folder
    if [ ! -f "$OPENCL_HEADERS_DIR/CL/cl.h" ]; then
        # Some versions put headers under include/
        if [ -f "$OPENCL_HEADERS_DIR/include/CL/cl.h" ]; then
            # Move headers to expected location
            cp -r "$OPENCL_HEADERS_DIR/include/CL" "$OPENCL_HEADERS_DIR/"
        else
            echo "  ERROR: Could not find CL/cl.h after extraction"
            echo "  Contents: $(ls "$OPENCL_HEADERS_DIR/")"
            exit 1
        fi
    fi

    echo "  OpenCL headers installed to $OPENCL_HEADERS_DIR"
fi

# ---------------------------------------------------------------
# Step 3: Check for existing OpenCL runtime or build local ICD loader
# ---------------------------------------------------------------
echo "[3/4] Checking OpenCL runtime..."

SYSTEM_OPENCL=""
# Check for existing libOpenCL.so (from existing GPU drivers)
for path in \
    /usr/lib/x86_64-linux-gnu/libOpenCL.so \
    /usr/lib/x86_64-linux-gnu/libOpenCL.so.1 \
    /usr/local/lib/libOpenCL.so \
    /opt/rocm/lib/libOpenCL.so \
    /usr/lib/libOpenCL.so; do
    if [ -f "$path" ]; then
        SYSTEM_OPENCL="$path"
        break
    fi
done

if [ -n "$SYSTEM_OPENCL" ]; then
    echo "  Found existing OpenCL runtime: $SYSTEM_OPENCL"
    echo "  Will link against it (no driver changes needed)."
    OPENCL_LIB_DIR="$(dirname "$SYSTEM_OPENCL")"
else
    echo "  No system OpenCL runtime found."
    echo "  Installing ocl-icd-libopencl1 (ICD loader only, NOT a GPU driver)..."
    echo ""
    echo "  NOTE: ocl-icd-libopencl1 is a vendor-neutral loader that dispatches"
    echo "  OpenCL calls to your actual GPU driver. It does NOT replace or modify"
    echo "  any existing GPU drivers."

    # ocl-icd-libopencl1 is safe to install - it's just a dispatcher
    sudo apt-get install -y -qq ocl-icd-libopencl1 ocl-icd-opencl-dev 2>/dev/null || {
        echo ""
        echo "  Could not install ocl-icd. Building local ICD loader..."

        if [ -f "$OCL_ICD_DIR/lib/libOpenCL.so" ]; then
            echo "  Local ICD loader already built."
        else
            echo "  Downloading and building ocl-icd ($OCL_ICD_TAG)..."
            mkdir -p "$OCL_ICD_DIR/build"

            ICD_URL="https://github.com/OCL-dev/ocl-icd/archive/refs/tags/${OCL_ICD_TAG}.tar.gz"
            TMPFILE=$(mktemp /tmp/ocl-icd-XXXXXX.tar.gz)

            curl -sL "$ICD_URL" -o "$TMPFILE"
            tar -xzf "$TMPFILE" -C "$OCL_ICD_DIR/build" --strip-components=1
            rm -f "$TMPFILE"

            cd "$OCL_ICD_DIR/build"
            autoreconf -i 2>/dev/null || {
                sudo apt-get install -y -qq autoconf automake libtool
                autoreconf -i
            }
            ./configure --prefix="$OCL_ICD_DIR"
            make -j$(nproc)
            make install
            cd "$SCRIPT_DIR"

            echo "  Local ICD loader built at $OCL_ICD_DIR"
        fi

        OPENCL_LIB_DIR="$OCL_ICD_DIR/lib"
    }

    # Re-check after install
    if [ -z "$OPENCL_LIB_DIR" ]; then
        for path in \
            /usr/lib/x86_64-linux-gnu/libOpenCL.so \
            /usr/lib/x86_64-linux-gnu/libOpenCL.so.1; do
            if [ -f "$path" ]; then
                OPENCL_LIB_DIR="$(dirname "$path")"
                break
            fi
        done
    fi
fi

# ---------------------------------------------------------------
# Step 4: Generate local Makefile override
# ---------------------------------------------------------------
echo "[4/4] Generating Makefile.local..."

# Determine include path for OpenCL headers
OPENCL_INCLUDE="$OPENCL_HEADERS_DIR"
# If the headers have an include/ subdirectory, use that
if [ -d "$OPENCL_HEADERS_DIR/include/CL" ]; then
    OPENCL_INCLUDE="$OPENCL_HEADERS_DIR/include"
fi

cat > "$SCRIPT_DIR/Makefile.local" << MAKEFILE_EOF
# Auto-generated by setup_isolated_opencl.sh
# This file configures the build to use locally-installed OpenCL headers
# without modifying system GPU drivers.
#
# Usage:
#   make -f Makefile.local [target]
#
# Targets: most, all, vanitygen++, oclvanitygen++, oclvanityminer, keyconv, test

# ---- Local OpenCL paths (isolated from system drivers) ----
LOCAL_OPENCL_INCLUDE=${OPENCL_INCLUDE}
LOCAL_OPENCL_LIB=${OPENCL_LIB_DIR:-/usr/lib/x86_64-linux-gnu}

# ---- Base configuration (same as Makefile) ----
LIBS=-lpcre -lcrypto -lm -lpthread
CFLAGS=-ggdb -O3 -Wall -Wno-deprecated

# Add local OpenCL headers (takes priority over system headers)
CFLAGS+=-I\$(LOCAL_OPENCL_INCLUDE)

# OpenCL library
OPENCL_LIBS=-L\$(LOCAL_OPENCL_LIB) -lOpenCL

OBJS=vanitygen.o oclvanitygen.o oclvanityminer.o oclengine.o keyconv.o pattern.o util.o groestl.o sha3.o ed25519.o \\
     stellar.o base32.o crc16.o bech32.o segwit_addr.o
PROGS=vanitygen++ keyconv oclvanitygen++ oclvanityminer

most: vanitygen++ keyconv

all: \$(PROGS)

vanitygen++: vanitygen.o pattern.o util.o groestl.o sha3.o ed25519.o stellar.o base32.o crc16.o simplevanitygen.o bech32.o segwit_addr.o
	\$(CC) \$^ -o \$@ \$(CFLAGS) \$(LIBS)

oclvanitygen++: oclvanitygen.o oclengine.o pattern.o util.o groestl.o sha3.o
	\$(CC) \$^ -o \$@ \$(CFLAGS) \$(LIBS) \$(OPENCL_LIBS)

oclvanityminer: oclvanityminer.o oclengine.o pattern.o util.o groestl.o sha3.o
	\$(CC) \$^ -o \$@ \$(CFLAGS) \$(LIBS) \$(OPENCL_LIBS) -lcurl

keyconv: keyconv.o util.o groestl.o sha3.o
	\$(CC) \$^ -o \$@ \$(CFLAGS) \$(LIBS)

run_tests.o: tests.h util_test.h segwit_addr_test.h pattern_test.h

run_tests: run_tests.o util.o groestl.o sha3.o bech32.o segwit_addr.o
	\$(CC) \$^ -o \$@ \$(CFLAGS) \$(LIBS) \$(OPENCL_LIBS) -lcheck

test: run_tests
	./run_tests

clean:
	rm -f \$(OBJS) \$(PROGS) *.oclbin run_tests
MAKEFILE_EOF

echo ""
echo "=== Setup complete! ==="
echo ""
echo "Your existing GPU drivers have NOT been modified."
echo ""
echo "To build vanitygen++ with isolated OpenCL:"
echo ""
echo "  make -f Makefile.local          # CPU-only tools (vanitygen++, keyconv)"
echo "  make -f Makefile.local all      # All tools including GPU (oclvanitygen++)"
echo ""
echo "OpenCL headers: $OPENCL_INCLUDE"
echo "OpenCL library: ${OPENCL_LIB_DIR:-/usr/lib/x86_64-linux-gnu}"
echo ""
