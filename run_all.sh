#!/usr/bin/env bash
# Trabalho 01 (MATC99) — regenera tudo de ponta a ponta: Parte I (AES-GCM) e Parte II (casos A/B/C).
# Uso: ./run_all.sh   (ou: bash run_all.sh)
set -euo pipefail
cd "$(dirname "$0")"

echo "=== Limpando artefatos gerados ==="
# Parte I
rm -f parte1/aes.key.hex parte1/aes.iv.hex parte1/chave_errada.hex \
      parte1/documento.gcm parte1/documento.tag.hex \
      parte1/documento.recuperado.txt parte1/documento_tamper.gcm
rm -f parte1/evidencias/*.log
# Parte II (pem/csr/srl/bin sao regenerados; privadas incluidas pois run_all regenera tudo)
rm -f parte2/*.pem parte2/*.csr.pem parte2/*.srl parte2/*.bin parte2/ext_entidade.cnf \
      parte2/documento_adulterado.txt
rm -f parte2/evidencias/*.log

echo
echo "=== Parte I: AES-256-GCM ==="
bash parte1/experimentos.sh

echo
echo "=== Parte II: assinaturas e certificados ==="
bash parte2/00_setup_cas.sh
bash parte2/01_caso_A.sh
bash parte2/02_caso_B.sh
bash parte2/03_caso_C.sh

echo
echo "Regeneracao concluida. Evidencias: parte1/evidencias/ e parte2/evidencias/"
