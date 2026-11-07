#!/usr/bin/env bash
# Caso A — assinatura do documento original + cadeia com a CA confiavel.
set -uo pipefail
cd "$(dirname "$0")"
mkdir -p evidencias

ULTIMO_RC=0
log_cmd() {
  local log="$1"; shift
  {
    echo "\$ $*"
    "$@" 2>&1
    ULTIMO_RC=$?
    echo "[exit: $ULTIMO_RC]"
  } > "$log"
  cat "$log"
}

rm -f assinatura_A.bin

# A1 — assinar o documento com RSA-PSS
log_cmd evidencias/p2_A1_assinar.log \
  openssl dgst -sha256 -sign entidade_A_privada.pem \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
    -out assinatura_A.bin documento.txt
if [ "$ULTIMO_RC" -ne 0 ]; then echo "ERRO INESPERADO: assinatura falhou"; exit 1; fi

# A2 — verificar a assinatura com a publica da Entidade A
log_cmd evidencias/p2_A2_verify.log \
  openssl dgst -sha256 -verify entidade_A_publica.pem \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
    -signature assinatura_A.bin documento.txt
if [ "$ULTIMO_RC" -ne 0 ] || ! grep -q "Verified OK" evidencias/p2_A2_verify.log; then
  echo "ERRO INESPERADO: verificacao da assinatura falhou"; exit 1
fi

# A3 — validar a cadeia com a CA confiavel
log_cmd evidencias/p2_A3_cadeia.log \
  openssl verify -CAfile ca_confiavel_cert.pem entidade_A_cert.pem
if [ "$ULTIMO_RC" -ne 0 ] || ! grep -q ": OK" evidencias/p2_A3_cadeia.log; then
  echo "ERRO INESPERADO: validacao da cadeia falhou"; exit 1
fi

echo
echo "Caso A concluido."
