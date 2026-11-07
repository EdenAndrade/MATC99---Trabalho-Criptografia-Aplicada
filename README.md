# MATC99 — Trabalho 01: Criptografia Aplicada

Parte I: cifragem autenticada com AES-256-GCM (AEAD).
Parte II: assinaturas RSA-PSS e cadeias de certificação (casos A/B/C).

## Pré-requisitos

- Linux ou WSL2 (testado em Ubuntu/WSL), bash
- OpenSSL 3.x (`openssl version`)
- Python 3 com a biblioteca `cryptography` (`pip install cryptography`),
  usada em `parte1/aead_gcm.py`

## Executar

```bash
./run_all.sh
```

Regenera chaves, cifra, assinaturas, certificados e as evidências em
`parte1/evidencias/` e `parte2/evidencias/` — cada log contém o comando
executado, a saída e o exit code. Chaves, evidências e demais artefatos
gerados ficam fora do git.
