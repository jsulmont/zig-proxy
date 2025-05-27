#!/bin/bash

echo "=== Testing Device Mapping Service ==="
echo "Your LFDI: 2D176C15902F9D9732E1960F813A1C3049675A42"
echo ""

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

echo -e "\n\n"

# Test 2: Send a Reading with mRID device identifier
echo "=== Test 2: Reading with mRID device identifier ==="
curl -v --http1.1 \
  --cert ./out/my-client-chain.pem \
  --key ./out/my-client.key \
  --cacert ./out/rootca-chain.pem \
  --tlsv1.2 \
  --ciphers ECDHE-ECDSA-AES128-GCM-SHA256 \
  -H "Content-Type: application/sep+xml" \
  -H "Accept: application/sep+xml" \
  --insecure \
  -d '<Reading xmlns="urn:ieee:std:2030.5:ns">
      <mRID>550e8400-e29b-41d4-a716-446655440001</mRID>
      <value>67890</value>
      <timestamp>1234567891</timestamp>
    </Reading>' \
  https://localhost:8443/mr

echo -e "\n\n"

# Test 3: Send a UsagePoint with deviceId
echo "=== Test 3: UsagePoint with deviceId ==="
curl -v --http1.1 \
  --cert ./out/my-client-chain.pem \
  --key ./out/my-client.key \
  --cacert ./out/rootca-chain.pem \
  --tlsv1.2 \
  --ciphers ECDHE-ECDSA-AES128-GCM-SHA256 \
  -H "Content-Type: application/sep+xml" \
  -H "Accept: application/sep+xml" \
  --insecure \
  -d '<UsagePoint xmlns="urn:ieee:std:2030.5:ns">
      <deviceId>SMART_METER_12345</deviceId>
      <description>Main electricity meter</description>
      <status>1</status>
    </UsagePoint>' \
  https://localhost:8443/upt

echo -e "\n\n"

# Test 4: Send an EndDevice with multiple identifiers (test precedence)
echo "=== Test 4: EndDevice with multiple identifiers (test precedence) ==="
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
      <serialNumber>SN123456789</serialNumber>
      <deviceId>DEVICE_XYZ_999</deviceId>
      <lfdi>HIGHPRIORITYLFDI567890ABCDEF1234567890AB</lfdi>
      <mRID>550e8400-e29b-41d4-a716-446655440002</mRID>
      <deviceCategory>0</deviceCategory>
      <enabled>true</enabled>
    </EndDevice>' \
  https://localhost:8443/edev

echo -e "\n\n"

# Test 5: Send a DERProgram with hwIdentifier
echo "=== Test 5: DERProgram with hwIdentifier ==="
curl -v --http1.1 \
  --cert ./out/my-client-chain.pem \
  --key ./out/my-client.key \
  --cacert ./out/rootca-chain.pem \
  --tlsv1.2 \
  --ciphers ECDHE-ECDSA-AES128-GCM-SHA256 \
  -H "Content-Type: application/sep+xml" \
  -H "Accept: application/sep+xml" \
  --insecure \
  -d '<DERProgram xmlns="urn:ieee:std:2030.5:ns">
      <hwIdentifier>HW_INVERTER_ABC123</hwIdentifier>
      <description>Solar inverter program</description>
      <primacy>1</primacy>
    </DERProgram>' \
  https://localhost:8443/derp

echo -e "\n\n"

echo "=== Testing Complete ==="
echo ""
echo "What to look for in the logs:"
echo "1. 'Aggregator device mapping' messages"
echo "2. 'Successfully extracted device identifier from aggregator'"
echo "3. 'Successfully stored device mapping' messages"
echo "4. Device extraction metrics"
echo ""
echo "Check Redis for stored mappings:"
echo "redis-cli KEYS 'device_mapping:*'"
echo "redis-cli KEYS 'aggregator_devices:*'"
