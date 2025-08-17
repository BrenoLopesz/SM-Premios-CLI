#!/usr/bin/env python3

import argparse
import sys
import pyfiglet
import commands

def main():
    """Configura a interface de linha de comando e executa o comando apropriado."""
    # print(pyfiglet.Figlet().getFonts())
    three_d_art = pyfiglet.figlet_format("SM Premios LTDA", font="larry3d")
    print(three_d_art)

    parser = argparse.ArgumentParser(
        description="Uma ferramenta CLI para verificar e inspecionar commitments de RNG.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- Sub-parser para 'check-match' ---
    parser_check = subparsers.add_parser("check-match", help="Verifica se uma seed em TEXTO PLANO corresponde a um hash de commitment.")
    parser_check.add_argument("--seed", required=True, help="A seed secreta em TEXTO PLANO (hex).")
    parser_check.add_argument("--event-id", required=True, help="A string identificadora do evento.")
    parser_check.add_argument("--metadata-file", required=True, help="Caminho para o arquivo JSON contendo os metadados.")
    parser_check.add_argument("--committed-hash", required=True, help="O hash de commitment (hex) para verificar.")
    parser_check.add_argument("--debug", action="store_true", help="Imprime a string exata que está sendo hasheada para depuração.")
    parser_check.set_defaults(func=commands.handle_check_match)

    # --- Sub-parser para 'generate-commitment' ---
    parser_generate = subparsers.add_parser("generate-commitment", help="Gera um hash de commitment a partir de uma seed em TEXTO PLANO.")
    parser_generate.add_argument("--seed", required=True, help="A seed secreta em TEXTO PLANO (hex).")
    parser_generate.add_argument("--event-id", required=True, help="A string identificadora do evento.")
    parser_generate.add_argument("--metadata-file", required=True, help="Caminho para o arquivo JSON contendo os metadados.")
    parser_generate.set_defaults(func=commands.handle_generate_commitment)

    # --- Sub-parser para 'verify-signature' ---
    parser_verify = subparsers.add_parser("verify-signature", help="Verifica a assinatura digital de um hash de commitment.")
    parser_verify.add_argument("--public-key-file", required=True, help="Caminho para o arquivo de chave pública codificado em PEM.")
    parser_verify.add_argument("--signature", required=True, help="A assinatura do hash (hex).")
    parser_verify.add_argument("--committed-hash", required=True, help="O hash de commitment que foi assinado (hex).")
    parser_verify.set_defaults(func=commands.handle_verify_signature)

    # --- NOVO: Sub-parser para 'verify-full-chain' ---
    parser_full_chain = subparsers.add_parser(
        "verify-full-chain",
        help="Descriptografa uma seed, re-hasheia e verifica se corresponde ao hash de commitment original.",
        description="""
Este comando realiza a verificação completa de ponta a ponta.
Ele prova que os dados criptografados armazenados pelo servidor correspondem ao commitment público.

Exemplo de Uso:
python seu_script.py verify-full-chain \\
    --encrypted-seed "..." \\
    --iv "..." \\
    --auth-tag "..." \\
    --decryption-key "..." \\
    --event-id "meu-evento-123" \\
    --metadata-file "metadata.json" \\
    --committed-hash "e3b0c442..." \\
    --debug

Nota: Por segurança, é melhor definir a chave de descriptografia como uma variável de ambiente:
export SEED_ENCRYPTION_KEY_HEX="..."
Assim você pode omitir o argumento --decryption-key.
"""
    )
    parser_full_chain.add_argument("--encrypted-seed", required=True, help="A seed criptografada do banco de dados (hex).")
    parser_full_chain.add_argument("--iv", required=True, help="O vetor de inicialização do banco de dados (hex).")
    parser_full_chain.add_argument("--auth-tag", required=True, help="A tag de autenticação do banco de dados (hex).")
    parser_full_chain.add_argument("--decryption-key", help="A chave secreta AES (hex). Também pode ser definida através da variável de ambiente SEED_ENCRYPTION_KEY_HEX.")
    parser_full_chain.add_argument("--event-id", required=True, help="A string identificadora do evento.")
    parser_full_chain.add_argument("--metadata-file", required=True, help="Caminho para o arquivo JSON contendo os metadados.")
    parser_full_chain.add_argument("--committed-hash", required=True, help="O hash de commitment original (hex) para verificar.")
    parser_full_chain.add_argument("--debug", action="store_true", help="Imprime a string exata que está sendo hasheada para depuração.")
    parser_full_chain.set_defaults(func=commands.handle_verify_full_chain)


    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    # A biblioteca 'cryptography' é uma dependência obrigatória.
    # Instale-a com: pip install cryptography
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        print("Erro: A biblioteca 'cryptography' não está instalada.", file=sys.stderr)
        print("Por favor, instale-a executando: pip install cryptography", file=sys.stderr)
        sys.exit(1)
        
    main()