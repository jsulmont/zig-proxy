# First get the LFDI
LFDI=$(openssl x509 -in ./out/my-client-chain.pem -fingerprint -sha1 -noout | sed 's/SHA1 Fingerprint=//g' | sed 's/://g' | tr '[:upper:]' '[:lower:]')

# Extract last 10 hex characters (40 bits)
LAST_10_HEX=${LFDI: -10}

# Convert to decimal
DEC=$(printf "%d" 0x$LAST_10_HEX)

# Format as 12-digit decimal with leading zeros
SFDI=$(printf "%012d" $DEC)

echo "LFDI: $LFDI"
echo "SFDI: $SFDI"
