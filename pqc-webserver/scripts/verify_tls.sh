#!/bin/bash

HOST=${1:-localhost}
PORT=${2:-443}
STAGE=${3:-auto}

echo "=== TLS 협상 결과 검증: $HOST:$PORT (Stage: $STAGE) ==="
echo ""

if [ "$STAGE" = "1" ] || [ "$STAGE" = "ecc" ]; then
    RESULT=$(openssl s_client -connect $HOST:$PORT \
        -CAfile /home/yulimH/quantum-jump/pqc-webserver/certs/ca.crt \
        -groups x25519:prime256v1:secp384r1 -brief 2>&1 </dev/null)
elif [ "$STAGE" = "2" ] || [ "$STAGE" = "hybrid" ]; then
    RESULT=$(openssl s_client -connect $HOST:$PORT \
        -CAfile /home/yulimH/quantum-jump/pqc-webserver/certs/ca.crt \
        -groups X25519MLKEM768:x25519 -brief 2>&1 </dev/null)
elif [ "$STAGE" = "3" ] || [ "$STAGE" = "pq" ]; then
    RESULT=$(openssl s_client -connect $HOST:$PORT \
        -CAfile /home/yulimH/quantum-jump/pqc-webserver/certs/ca.crt \
        -groups p521_mlkem1024:p384_mlkem768 -brief 2>&1 </dev/null)
else
    RESULT=$(openssl s_client -connect $HOST:$PORT \
        -CAfile /home/yulimH/quantum-jump/pqc-webserver/certs/ca.crt \
        -brief 2>&1 </dev/null)
fi

echo "$RESULT"
echo ""

PROTOCOL=$(echo "$RESULT" | grep "Protocol version" | awk '{print $NF}')
CIPHER=$(echo "$RESULT" | grep "Ciphersuite" | awk '{print $NF}')
GROUP=$(echo "$RESULT" | grep -E "Negotiated TLS1.3 group|Peer Temp Key" | cut -d: -f2- | tr -d ' ')

echo "=== 요약 ==="
echo "Protocol : $PROTOCOL"
echo "Cipher   : $CIPHER"
echo "Key Group: $GROUP"

if echo "$GROUP" | grep -qi "MLKEM\|mlkem"; then
    if echo "$GROUP" | grep -qi "X25519\|p256\|p384"; then
        echo "판정: Stage 2 - Hybrid PQC-TLS"
    else
        echo "판정: Stage 3 - Post-Quantum TLS"
    fi
else
    echo "판정: Stage 1 - Classical TLS (ECC)"
fi
