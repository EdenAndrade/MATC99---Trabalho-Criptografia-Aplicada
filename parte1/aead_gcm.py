#!/usr/bin/env python3
"""Cifra/decifra AES-256-GCM com chave e IV em arquivos .hex."""
import argparse
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TAM_TAG = 16  # tag GCM padrao: 128 bits
FALHA = "FALHA: tag de autenticação invalida - conteudo alterado OU chave incorreta"


def ler_hex(caminho: str) -> bytes:
    with open(caminho, "r", encoding="ascii") as f:
        return bytes.fromhex(f.read().strip())


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cifra/decifra AES-256-GCM com chave e IV em arquivos .hex")
    sub = parser.add_subparsers(dest="comando", required=True)

    comum = argparse.ArgumentParser(add_help=False)
    comum.add_argument("--key-file", required=True, help="arquivo .hex com a chave (32 bytes)")
    comum.add_argument("--iv-file", required=True, help="arquivo .hex com o IV (12 bytes)")
    comum.add_argument("--in", dest="arquivo_in", required=True)
    comum.add_argument("--out", dest="arquivo_out", required=True)
    for nome in ("encrypt", "decrypt"):
        p = sub.add_parser(nome, parents=[comum])
        p.add_argument("--tag-file", required=True, help="arquivo da tag GCM (hex)")

    args = parser.parse_args()

    chave = ler_hex(args.key_file)
    iv = ler_hex(args.iv_file)
    if len(chave) != 32:
        print(f"ERRO: chave deve ter 32 bytes (recebidos {len(chave)})", file=sys.stderr)
        return 2
    if len(iv) != 12:
        print(f"ERRO: IV do GCM deve ter 12 bytes (recebidos {len(iv)})", file=sys.stderr)
        return 2

    with open(args.arquivo_in, "rb") as f:
        dados = f.read()

    if args.comando == "encrypt":
        ct_com_tag = AESGCM(chave).encrypt(iv, dados, None)
        ciphertext, tag = ct_com_tag[:-TAM_TAG], ct_com_tag[-TAM_TAG:]
        with open(args.arquivo_out, "wb") as f:
            f.write(ciphertext)
        with open(args.tag_file, "w", encoding="ascii") as f:
            f.write(tag.hex() + "\n")
        print(f"OK: {len(dados)} bytes cifrados -> {len(ciphertext)} bytes de ciphertext")
        print(f"OK: tag GCM de {TAM_TAG} bytes gravada em {args.tag_file}")
        return 0

    # decrypt
    tag = ler_hex(args.tag_file)
    try:
        texto = AESGCM(chave).decrypt(iv, dados + tag, None)
    except InvalidTag:
        print(FALHA, file=sys.stderr)
        return 1
    with open(args.arquivo_out, "wb") as f:
        f.write(texto)
    print(f"OK: autenticacao e descriptografia bem-sucedidas ({len(texto)} bytes recuperados)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
