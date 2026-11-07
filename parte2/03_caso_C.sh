#!/usr/bin/env bash
# Caso C — documento integro; o certificado da Entidade C foi emitido por uma CA rogue.
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

rm -f assinatura_C.bin

# C1 — assinar o documento (INTEGRO) com a chave da Entidade C
log_cmd evidencias/p2_C1_assinar.log \
  openssl dgst -sha256 -sign entidade_C_privada.pem \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
    -out assinatura_C.bin documento.txt
if [ "$ULTIMO_RC" -ne 0 ]; then echo "ERRO INESPERADO: assinatura do caso C falhou"; exit 1; fi

# C2 — verificar a assinatura com a publica da Entidade C
log_cmd evidencias/p2_C2_verify.log \
  openssl dgst -sha256 -verify entidade_C_publica.pem \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
    -signature assinatura_C.bin documento.txt
if [ "$ULTIMO_RC" -ne 0 ] || ! grep -q "Verified OK" evidencias/p2_C2_verify.log; then
  echo "ERRO INESPERADO: verificacao da assinatura falhou"; exit 1
fi

# C3 — validar a cadeia com a CA confiavel
log_cmd evidencias/p2_C3_cadeia.log \
  openssl verify -CAfile ca_confiavel_cert.pem entidade_C_cert.pem
if [ "$ULTIMO_RC" -eq 0 ] || grep -q ": OK" evidencias/p2_C3_cadeia.log; then
  echo "ERRO INESPERADO: cadeia validada com a CA confiavel"; exit 1
fi

# C4 — dump subject/issuer dos certificados A e C
{
  echo "$ openssl x509 -noout -subject -issuer -in entidade_A_cert.pem"
  openssl x509 -noout -subject -issuer -in entidade_A_cert.pem
  echo
  echo "$ openssl x509 -noout -subject -issuer -in entidade_C_cert.pem"
  openssl x509 -noout -subject -issuer -in entidade_C_cert.pem
} > evidencias/p2_C4_certificados.log
cat evidencias/p2_C4_certificados.log

echo
echo "Caso C concluido."
