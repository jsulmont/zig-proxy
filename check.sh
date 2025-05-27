#!/bin/bash

# Check your client certificate details
echo "=== Certificate Analysis ==="

# 1. Basic certificate info
echo "1. Basic Certificate Information:"
openssl x509 -in ./out/my-client-chain.pem -text -noout | head -20

echo -e "\n2. Subject and Issuer:"
openssl x509 -in ./out/my-client-chain.pem -subject -issuer -noout

echo -e "\n3. Subject Alternative Names (SAN):"
openssl x509 -in ./out/my-client-chain.pem -text -noout | grep -A 10 "Subject Alternative Name"

echo -e "\n4. Certificate Extensions (all):"
openssl x509 -in ./out/my-client-chain.pem -text -noout | grep -A 100 "X509v3 extensions:"

echo -e "\n5. Hardware Module Name (if present):"
openssl x509 -in ./out/my-client-chain.pem -text -noout | grep -A 5 -B 5 "1.3.6.1.5.5.7.8.4"

echo -e "\n6. Certificate Policies:"
openssl x509 -in ./out/my-client-chain.pem -text -noout | grep -A 10 "Certificate Policies"

echo -e "\n7. ASN.1 dump (to see OIDs):"
openssl asn1parse -i -in ./out/my-client-chain.pem | grep -E "(OBJECT|UTF8)"

echo -e "\n8. Full ASN.1 structure:"
openssl asn1parse -i -in ./out/my-client-chain.pem

echo -e "\n=== Certificate Fingerprint ==="
echo "SHA1:"
openssl x509 -in ./out/my-client-chain.pem -fingerprint -sha1 -noout

echo "SHA256:"
openssl x509 -in ./out/my-client-chain.pem -fingerprint -sha256 -noout

echo -e "\n=== Expected LFDI (first 40 chars of SHA256 fingerprint without colons) ==="
openssl x509 -in ./out/my-client-chain.pem -fingerprint -sha256 -noout | sed 's/.*=//' | tr -d ':' | cut -c1-40
