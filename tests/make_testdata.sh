#!/usr/bin/env bash
# 產生測試用的憑證鏈與各種格式（需要 openssl，Git for Windows 內建）
# 用法：bash tests/make_testdata.sh <輸出目錄>
set -euo pipefail
OUT="${1:?請指定輸出目錄}"
mkdir -p "$OUT"
cd "$OUT"
export MSYS_NO_PATHCONV=1
PASS=test123

cat > ca.ext <<'EOF'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
cat > leaf.ext <<'EOF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:www.example.test,DNS:example.test
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF

# 根 CA（自簽）
openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.crt -days 3650 \
  -subj "/C=TW/O=Test Org/CN=Test Root CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
# 中繼 CA
openssl req -newkey rsa:2048 -nodes -keyout inter.key -out inter.csr -subj "/C=TW/O=Test Org/CN=Test Intermediate CA" 2>/dev/null
openssl x509 -req -in inter.csr -CA root.crt -CAkey root.key -CAcreateserial -out inter.crt -days 1825 -extfile ca.ext 2>/dev/null
# 終端憑證（RSA）
openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj "/C=TW/O=Test Org/CN=www.example.test" 2>/dev/null
openssl x509 -req -in leaf.csr -CA inter.crt -CAkey inter.key -CAcreateserial -out leaf.crt -days 397 -extfile leaf.ext 2>/dev/null
# 終端憑證（EC P-256，SEC1 格式私鑰）
openssl ecparam -name prime256v1 -genkey -out ec.key 2>/dev/null
openssl req -new -key ec.key -out ec.csr -subj "/C=TW/O=Test Org/CN=ec.example.test" 2>/dev/null
openssl x509 -req -in ec.csr -CA inter.crt -CAkey inter.key -CAcreateserial -out ec.crt -days 397 -extfile leaf.ext 2>/dev/null

# 私鑰各種格式
openssl rsa -in leaf.key -traditional -out leaf_pkcs1.key 2>/dev/null
openssl pkcs8 -topk8 -in leaf.key -v2 aes-256-cbc -passout pass:$PASS -out leaf_pbes2.key
openssl pkcs8 -topk8 -in leaf.key -v2 aes-128-cbc -v2prf hmacWithSHA1 -passout pass:$PASS -out leaf_pbes2_sha1.key
openssl rsa -in leaf.key -aes256 -traditional -passout pass:$PASS -out leaf_legacy_enc.key 2>/dev/null
openssl rsa -in leaf.key -outform DER -out leaf_key.der 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in ec.key -out ec_pkcs8.key

# 憑證容器
openssl x509 -in leaf.crt -outform DER -out leaf.der
cat inter.crt root.crt leaf.crt > bundle_shuffled.pem
cat inter.crt root.crt > cachain.pem
openssl crl2pkcs7 -nocrl -certfile leaf.crt -certfile inter.crt -certfile root.crt -out chain_pem.p7b
openssl crl2pkcs7 -nocrl -certfile leaf.crt -certfile inter.crt -certfile root.crt -outform DER -out chain.p7b
openssl pkcs12 -export -in leaf.crt -inkey leaf.key -certfile cachain.pem -passout pass:$PASS -out leaf_aes.pfx
openssl pkcs12 -export -in leaf.crt -inkey leaf.key -certfile cachain.pem -passout pass:$PASS \
  -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 -out leaf_3des.pfx
openssl pkcs12 -export -in ec.crt -inkey ec.key -passout pass: -out ec_nopass.pfx

rm -f *.csr *.srl ca.ext leaf.ext cachain.pem
ls
