#!/usr/bin/env bash
# Parte II — setup: gera 2 CAs autoassinadas + 2 entidades (A, C) com OpenSSL CLI.
# Chaves privadas ficam fora do git (regeneradas por run_all.sh).
set -euo pipefail
umask 077
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

# limpa artefatos de execucoes anteriores
rm -f *.pem *.csr.pem *.srl ext_entidade.cnf
rm -f evidencias/*.log

# CA confiavel (autoassinada)
log_cmd evidencias/p2_00_ca_confiavel.log \
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout ca_confiavel_privada.pem -out ca_confiavel_cert.pem \
    -days 365 \
    -subj "/C=BR/O=XYZW LTDA/CN=CA Confiavel XYZW" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

# CA rogue (autoassinada)
log_cmd evidencias/p2_00_ca_rogue.log \
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout ca_rogue_privada.pem -out ca_rogue_cert.pem \
    -days 365 \
    -subj "/C=BR/O=Certificadora Desconhecida/CN=CA Rogue" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

# extensao para as entidades folha
cat > ext_entidade.cnf <<'EOF'
basicConstraints = CA:FALSE
keyUsage = digitalSignature
EOF

# Entidade A — cert emitido pela CA confiavel
log_cmd evidencias/p2_00_entidade_A_chave.log \
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out entidade_A_privada.pem
log_cmd evidencias/p2_00_entidade_A_csr.log \
  openssl req -new -key entidade_A_privada.pem \
    -out entidade_A.csr.pem \
    -subj "/C=BR/O=XYZW LTDA/CN=entidade-A.xyzw.com.br"
log_cmd evidencias/p2_00_entidade_A_cert.log \
  openssl x509 -req -in entidade_A.csr.pem \
    -CA ca_confiavel_cert.pem -CAkey ca_confiavel_privada.pem \
    -CAcreateserial -days 365 -extfile ext_entidade.cnf \
    -out entidade_A_cert.pem
log_cmd evidencias/p2_00_entidade_A_publica.log \
  openssl pkey -in entidade_A_privada.pem -pubout -out entidade_A_publica.pem

# Entidade C — cert emitido pela CA rogue
log_cmd evidencias/p2_00_entidade_C_chave.log \
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out entidade_C_privada.pem
log_cmd evidencias/p2_00_entidade_C_csr.log \
  openssl req -new -key entidade_C_privada.pem \
    -out entidade_C.csr.pem \
    -subj "/C=BR/O=XYZW LTDA/CN=entidade-C.xyzw.com.br"
log_cmd evidencias/p2_00_entidade_C_cert.log \
  openssl x509 -req -in entidade_C.csr.pem \
    -CA ca_rogue_cert.pem -CAkey ca_rogue_privada.pem \
    -CAcreateserial -days 365 -extfile ext_entidade.cnf \
    -out entidade_C_cert.pem
log_cmd evidencias/p2_00_entidade_C_publica.log \
  openssl pkey -in entidade_C_privada.pem -pubout -out entidade_C_publica.pem

chmod 600 *_privada.pem

# resumo: subject/issuer dos 4 certificados
{
  echo "$ openssl x509 -noout -subject -issuer -in <cert>"
  for c in ca_confiavel_cert ca_rogue_cert entidade_A_cert entidade_C_cert; do
    echo "--- $c.pem"
    openssl x509 -noout -subject -issuer -in "$c.pem"
  done
} > evidencias/p2_00_resumo.log
cat evidencias/p2_00_resumo.log

# sanity: os 8 arquivos obrigatorios existem
for f in ca_confiavel_privada.pem ca_confiavel_cert.pem \
         ca_rogue_privada.pem ca_rogue_cert.pem \
         entidade_A_privada.pem entidade_A_cert.pem entidade_A_publica.pem \
         entidade_C_privada.pem entidade_C_cert.pem entidade_C_publica.pem; do
  [ -s "$f" ] || { echo "ERRO: $f nao foi gerado"; exit 1; }
done

echo
echo "Setup Parte II concluido: 2 CAs + 2 entidades."
