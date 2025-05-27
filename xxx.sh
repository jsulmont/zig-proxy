#!/bin/bash

# Test 1: Send a MeterReading with an LFDI (highest priority device identifier)
echo "=== Test 1: MeterReading with LFDI device identifier ==="
curl -v --http1.1 \
  --cert ./out/my-client-chain.pem \
  --key ./out/my-client.key \
  --cacert ./out/rootca-chain.pem \
  --tlsv1.2 \
  --ciphers ECDHE-ECDSA-AES128-GCM-SHA256 \
  -H "Content-Type: application/sep+xml" \
  -H "Accept: application/sep+xml" \
  --insecure \
  -d '<MeterReading xmlns="urn:ieee:std:2030.5:ns">
      <lfdi>DEVICE001LFDI1234567890ABCDEF1234567890</lfdi>
      <value>12345</value>
      <timestamp>1234567890</timestamp>
    </MeterReading>' \
  https://localhost:8443/mr

