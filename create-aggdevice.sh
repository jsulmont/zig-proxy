curl --http1.1 \
  --cert ./out/my-client-chain.pem \
  --key ./out/my-client.key \
  --cacert ./out/rootca-chain.pem \
  --tlsv1.2 \
  --ciphers ECDHE-ECDSA-AES128-GCM-SHA256 \
  -H "Content-Type: application/sep+xml" \
  -H "Accept: application/sep+xml" \
  --insecure \
  -d '<EndDevice xmlns="urn:ieee:std:2030.5:ns">
      <deviceCategory>0</deviceCategory>
      <sFDI>0</sFDI>
      <enabled>true</enabled>
    </EndDevice>' \
  https://localhost:8443/edev
