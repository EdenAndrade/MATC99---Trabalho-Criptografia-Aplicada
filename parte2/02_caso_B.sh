#!/usr/bin/env bash
# Caso B — o documento e alterado apos a assinatura (VALOR=100 vira VALOR=900);
# a assinatura original nao e refeita.
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

# B1 — adulterar o documento (sed) e registrar a diferenca
log_cmd evidencias/p2_B1_adulterar.log \
  sed 's/VALOR=100/VALOR=900/' documento.txt
sed 's/VALOR=100/VALOR=900/' documento.txt > documento_adulterado.txt
{
  echo '$ diff -u documento.txt documento_adulterado.txt'
  diff -u documento.txt documento_adulterado.txt || true
} > evidencias/p2_B1b_diff.log
cat evidencias/p2_B1b_diff.log

# B2 — hashes do original e do adulterado, lado a lado
{
  echo '$ openssl dgst -sha256 documento.txt documento_adulterado.txt'
  openssl dgst -sha256 documento.txt documento_adulterado.txt
} > evidencias/p2_B2_hashes.log
cat evidencias/p2_B2_hashes.log

# B3 — verificar a assinatura original contra o documento adulterado
log_cmd evidencias/p2_B3_verify.log \
  openssl dgst -sha256 -verify entidade_A_publica.pem \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
    -signature assinatura_A.bin documento_adulterado.txt
if [ "$ULTIMO_RC" -eq 0 ] || ! grep -q "Verification failure" evidencias/p2_B3_verify.log; then
  echo "ERRO INESPERADO: verificacao do documento adulterado nao retornou Verification failure"; exit 1
fi

echo
echo "Caso B concluido."
