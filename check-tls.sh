#!/bin/bash
# TLS Configuration Testing Script for IEEE 2030.5 Proxy
# This script uses testssl.sh to verify TLS configuration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Check if testssl.sh is installed
if ! command -v testssl.sh &> /dev/null; then
    echo -e "${YELLOW}testssl.sh not found. Installing...${NC}"
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git
    cd testssl.sh
    chmod +x testssl.sh
    TESTSSL="./testssl.sh"
else
    TESTSSL="testssl.sh"
fi

# Function to run tests
run_tls_test() {
    local host=$1
    local port=$2
    local description=$3

    echo -e "${YELLOW}Running TLS test on ${host}:${port} (${description})${NC}"

    # Run basic protocol check first
    echo -e "${YELLOW}Checking protocols...${NC}"
    $TESTSSL -p "${host}:${port}"

    # Check specifically for disabled protocols
    echo -e "${YELLOW}Verifying SSLv2 is disabled...${NC}"
    if $TESTSSL -p --ssl2 "${host}:${port}" | grep -q "not offered"; then
        echo -e "${GREEN}SSLv2 is correctly disabled${NC}"
    else
        echo -e "${RED}ERROR: SSLv2 might be enabled!${NC}"
    fi

    echo -e "${YELLOW}Verifying SSLv3 is disabled...${NC}"
    if $TESTSSL -p --ssl3 "${host}:${port}" | grep -q "not offered"; then
        echo -e "${GREEN}SSLv3 is correctly disabled${NC}"
    else
        echo -e "${RED}ERROR: SSLv3 might be enabled!${NC}"
    fi

    echo -e "${YELLOW}Verifying TLS 1.0 is disabled...${NC}"
    if $TESTSSL -p --tls1 "${host}:${port}" | grep -q "not offered"; then
        echo -e "${GREEN}TLS 1.0 is correctly disabled${NC}"
    else
        echo -e "${RED}ERROR: TLS 1.0 might be enabled!${NC}"
    fi

    echo -e "${YELLOW}Verifying TLS 1.1 is disabled...${NC}"
    if $TESTSSL -p --tls1_1 "${host}:${port}" | grep -q "not offered"; then
        echo -e "${GREEN}TLS 1.1 is correctly disabled${NC}"
    else
        echo -e "${RED}ERROR: TLS 1.1 might be enabled!${NC}"
    fi

    echo -e "${YELLOW}Verifying TLS 1.2 is enabled...${NC}"
    if $TESTSSL -p --tls1_2 "${host}:${port}" | grep -q "offered"; then
        echo -e "${GREEN}TLS 1.2 is correctly enabled${NC}"
    else
        echo -e "${RED}ERROR: TLS 1.2 is not enabled!${NC}"
    fi

    # Check cipher strength
    echo -e "${YELLOW}Checking for NULL ciphers...${NC}"
    if $TESTSSL -n "${host}:${port}" | grep -q "not vulnerable"; then
        echo -e "${GREEN}No NULL ciphers offered${NC}"
    else
        echo -e "${RED}ERROR: NULL ciphers might be enabled!${NC}"
    fi

    echo -e "${YELLOW}Checking for Anonymous ciphers...${NC}"
    if $TESTSSL --vulnerable "${host}:${port}" | grep -q "not vulnerable to ANON"; then
        echo -e "${GREEN}No Anonymous ciphers offered${NC}"
    else
        echo -e "${RED}ERROR: Anonymous ciphers might be enabled!${NC}"
    fi

    # Check for supported cipher suites
    echo -e "${YELLOW}Checking IEEE 2030.5 required cipher suite...${NC}"
    if $TESTSSL -c "${host}:${port}" | grep -q "ECDHE-ECDSA-AES128-CCM8\|ECDHE-ECDSA-AES128-GCM-SHA256"; then
        echo -e "${GREEN}IEEE 2030.5 compatible cipher offered${NC}"
    else
        echo -e "${RED}WARNING: IEEE 2030.5 compatible cipher not detected!${NC}"
    fi

    # Full cipher suite test (optional - can be commented out as it's verbose)
    echo -e "${YELLOW}Full cipher suite check...${NC}"
    $TESTSSL --cipher-per-proto "${host}:${port}"

    echo -e "${GREEN}Test completed for ${host}:${port}${NC}"
    echo ""
}

# Main script
echo -e "${YELLOW}IEEE 2030.5 Proxy TLS Configuration Test${NC}"
echo -e "${YELLOW}=====================================${NC}"

# Check if host and port were provided
if [ $# -lt 2 ]; then
    echo "Usage: $0 <host> <port> [description]"
    echo "Example: $0 localhost 8443 \"Local development server\""
    exit 1
fi

HOST=$1
PORT=$2
DESCRIPTION=${3:-"IEEE 2030.5 Proxy"}

run_tls_test "$HOST" "$PORT" "$DESCRIPTION"

echo -e "${GREEN}All tests completed.${NC}"
