#!/bin/bash

# Test script to debug HTTP parsing issues

echo "Testing HTTP parsing with simple request first..."

# Test 1: Simple GET request
echo "=== Test 1: Simple GET request ==="
curl -v --http1.1 \
  --cert ./out/my-client-chain.pem \
  --key ./out/my-client.key \
  --cacert ./out/rootca-chain.pem \
  --tlsv1.2 \
  --ciphers ECDHE-ECDSA-AES128-GCM-SHA256 \
  --insecure \
  https://127.0.0.1:8443/health

echo -e "\n\n=== Test 2: Simple POST without body ==="
curl -v --http1.1 \
  --cert ./out/my-client-chain.pem \
  --key ./out/my-client.key \
  --cacert ./out/rootca-chain.pem \
  --tlsv1.2 \
  --ciphers ECDHE-ECDSA-AES128-GCM-SHA256 \
  -X POST \
  --insecure \
  https://127.0.0.1:8443/edev

echo -e "\n\n=== Test 3: POST with small body ==="
curl -v --http1.1 \
  --cert ./out/my-client-chain.pem \
  --key ./out/my-client.key \
  --cacert ./out/rootca-chain.pem \
  --tlsv1.2 \
  --ciphers ECDHE-ECDSA-AES128-GCM-SHA256 \
  -H "Content-Type: application/sep+xml" \
  -d '<test>hello</test>' \
  --insecure \
  https://127.0.0.1:8443/edev

echo -e "\n\n=== Test 4: Original request ==="
curl -v --http1.1 \
  --cert ./out/my-client-chain.pem \
  --key ./out/my-client.key \
  --cacert ./out/rootca-chain.pem \
  --tlsv1.2 \
  --ciphers ECDHE-ECDSA-AES128-GCM-SHA256 \
  -H "Content-Type: application/sep+xml" \
  -H "Accept: application/sep+xml" \
  --insecure \
  -d '<EndDevice xmlns="urn:ieee:std:2030.5:ns">
      <sFDI>198325674429</sFDI>
      <lFDI>49e1cf69294c0588202f4f2cbd4f80044902ca51</lFDI>
      <changedTime>1379905200</changedTime>
      <deviceCategory>0f</deviceCategory>
    </EndDevice>' \
  https://127.0.0.1:8443/edev
