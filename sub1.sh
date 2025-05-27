curl -v --http1.1 \
  --cert ./out/my-client-chain.pem \
  --key ./out/my-client.key \
  --cacert ./out/rootca-chain.pem \
  --tlsv1.2 \
  --ciphers ECDHE-ECDSA-AES128-GCM-SHA256 \
  -H "Content-Type: application/sep+xml" \
  -H "Accept: application/sep+xml" \
  --insecure \
  -d '<Subscription xmlns="urn:ieee:std:2030.5:ns">
      <subscribedResource>/edev</subscribedResource>
      <encoding>0</encoding>
      <level>+S1</level>
      <limit>1</limit>
      <notificationURI>https://127.0.0.1:7777/notify</notificationURI>
    </Subscription>' \
  https://localhost:8443/edev/1/sub
