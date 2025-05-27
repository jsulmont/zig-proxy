#!/bin/bash

echo "=== Testing GET individual subscription ==="
curl --http1.1 \
  --cert ./out/my-client-chain.pem \
  --key ./out/my-client.key \
  --cacert ./out/rootca-chain.pem \
  --tlsv1.2 \
  --ciphers ECDHE-ECDSA-AES128-GCM-SHA256 \
  -H "Accept: application/sep+xml" \
  --insecure \
  https://localhost:8443/edev/1/sub/1

echo -e "\n\n=== Testing GET subscription list ==="
curl --http1.1 \
  --cert ./out/my-client-chain.pem \
  --key ./out/my-client.key \
  --cacert ./out/rootca-chain.pem \
  --tlsv1.2 \
  --ciphers ECDHE-ECDSA-AES128-GCM-SHA256 \
  -H "Accept: application/sep+xml" \
  --insecure \
  https://localhost:8443/edev/1/sub
