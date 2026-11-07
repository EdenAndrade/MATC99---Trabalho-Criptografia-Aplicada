#!/usr/bin/env bash
# Parte I — experimentos com AES-256-GCM.
# Cada passo grava evidencia em evidencias/p1_NN_descricao.log: comando + saida + exit code.
set -uo pipefail
cd "$(dirname "$0")"
mkdir -p evidencias

ULTIMO_RC=0
log_cmd() {
  # log_cmd <caminho-do-log> <comando> [args...] — grava comando, saida e exit code
  local log="$1"; shift
  {
    echo "\$ $*"
    "$@" 2>&1
    ULTIMO_RC=$?
    echo "[exit: $ULTIMO_RC]"
  } > "$log"
  cat "$log"
}

# p1_01 — documento comercial ficticio
{
  echo '$ cat documento_comercial.txt'
  cat documento_comercial.txt
} > evidencias/p1_01_documento.log
cat evidencias/p1_01_documento.log

# p1_02 — chave AES-256 (32 bytes) e IV GCM (12 bytes) em .hex
openssl rand -hex 32 > aes.key.hex
openssl rand -hex 12 > aes.iv.hex
chmod 600 aes.key.hex aes.iv.hex
{
  echo '$ openssl rand -hex 32 > aes.key.hex'
  echo '$ openssl rand -hex 12 > aes.iv.hex'
  echo '$ wc -c aes.key.hex aes.iv.hex'
  wc -c aes.key.hex aes.iv.hex
} > evidencias/p1_02_chave_iv.log
cat evidencias/p1_02_chave_iv.log

# p1_03 — cifrar com GCM
log_cmd evidencias/p1_03_cifrar.log \
  python3 aead_gcm.py encrypt --key-file aes.key.hex --iv-file aes.iv.hex \
    --in documento_comercial.txt --out documento.gcm --tag-file documento.tag.hex
if [ "$ULTIMO_RC" -ne 0 ]; then echo "ERRO INESPERADO: cifragem falhou"; exit 1; fi
log_cmd evidencias/p1_03b_hexdump.log hexdump -C documento.gcm

# p1_04 — decifrar com a chave correta e comparar
log_cmd evidencias/p1_04_decifrar.log \
  python3 aead_gcm.py decrypt --key-file aes.key.hex --iv-file aes.iv.hex \
    --in documento.gcm --tag-file documento.tag.hex --out documento.recuperado.txt
if [ "$ULTIMO_RC" -ne 0 ]; then echo "ERRO INESPERADO: decifragem com a chave correta falhou"; exit 1; fi

{
  echo '$ cmp -s documento_comercial.txt documento.recuperado.txt && echo IGUAIS'
  if cmp -s documento_comercial.txt documento.recuperado.txt; then
    echo "IGUAIS: documento recuperado identico ao original"
  else
    echo "DIFERENTES: decifragem nao reproduziu o original"
  fi
  echo
  echo '$ openssl dgst -sha256 documento_comercial.txt documento.recuperado.txt'
  openssl dgst -sha256 documento_comercial.txt documento.recuperado.txt
} > evidencias/p1_04b_comparacao.log
cat evidencias/p1_04b_comparacao.log
if ! grep -q "IGUAIS" evidencias/p1_04b_comparacao.log; then
  echo "ERRO INESPERADO: decifragem nao reproduziu o original"; exit 1
fi

# p1_05 — adulterar 1 byte do ciphertext (copia)
cp documento.gcm documento_tamper.gcm
{
  byte=$(dd if=documento_tamper.gcm bs=1 skip=10 count=1 2>/dev/null | od -An -tu1 | tr -d ' \n')
  flip=$(( byte ^ 255 ))
  printf \\$(printf '%03o' "$flip") | dd of=documento_tamper.gcm bs=1 seek=10 count=1 conv=notrunc 2>/dev/null
  echo "byte 10: $byte (0x$(printf '%02x' "$byte")) -> $flip (0x$(printf '%02x' "$flip"))"
  echo
  echo '$ cmp -l documento.gcm documento_tamper.gcm'
  cmp -l documento.gcm documento_tamper.gcm
} > evidencias/p1_05_tamper.log
cat evidencias/p1_05_tamper.log

log_cmd evidencias/p1_05b_tamper_decrypt.log \
  python3 aead_gcm.py decrypt --key-file aes.key.hex --iv-file aes.iv.hex \
    --in documento_tamper.gcm --tag-file documento.tag.hex --out /dev/null
if [ "$ULTIMO_RC" -eq 0 ] || ! grep -q "FALHA" evidencias/p1_05b_tamper_decrypt.log; then
  echo "ERRO INESPERADO: decifragem do ciphertext adulterado nao retornou FALHA"; exit 1
fi

# p1_06 — decifrar o ciphertext original com outra chave
openssl rand -hex 32 > chave_errada.hex
chmod 600 chave_errada.hex
{
  echo '$ openssl rand -hex 32 > chave_errada.hex'
} > evidencias/p1_06_chave_errada.log
cat evidencias/p1_06_chave_errada.log

log_cmd evidencias/p1_06b_chave_errada_decrypt.log \
  python3 aead_gcm.py decrypt --key-file chave_errada.hex --iv-file aes.iv.hex \
    --in documento.gcm --tag-file documento.tag.hex --out /dev/null
if [ "$ULTIMO_RC" -eq 0 ] || ! grep -q "FALHA" evidencias/p1_06b_chave_errada_decrypt.log; then
  echo "ERRO INESPERADO: decifragem com a outra chave nao retornou FALHA"; exit 1
fi

echo
echo "Parte I concluida: evidencias em evidencias/."
