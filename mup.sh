curl -v --http1.1 \
  --cert ./out/my-client-chain.pem \
  --key ./out/my-client.key \
  --cacert ./out/rootca-chain.pem \
  --tlsv1.2 \
  --ciphers ECDHE-ECDSA-AES128-GCM-SHA256 \
  -H "Content-Type: application/xml" \
  --insecure \
  --data-binary @bug/bad-mup-payload.xml \
  https://localhost:8443/mup
