import json
import sys
import os
import crypto_utils

def handle_check_match(args):
    """Manipulador para o comando 'check-match'."""
    print("--- Verificando se a Seed em Texto Plano Corresponde ao Commitment ---")
    try:
        with open(args.metadata_file, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Erro ao ler o arquivo de metadados: {e}", file=sys.stderr)
        sys.exit(1)

    if args.debug:
        pre_hash_string = crypto_utils.get_pre_hash_string(args.seed, args.event_id, metadata)
        print(f"\n[DEBUG] String que está sendo hasheada:\n---\n{pre_hash_string}\n---\n")

    generated_hash = crypto_utils.compute_commitment_hash(args.seed, args.event_id, metadata)

    print(f"   ID do Evento: {args.event_id}")
    print(f"   Seed em Texto Plano Usada: {args.seed[:16]}...")
    print(f"   Hash Gerado: {generated_hash}")
    print(f"   Hash Fornecido:  {args.committed_hash}")

    if generated_hash == args.committed_hash:
        print("\n✅ SUCESSO: A seed em texto plano fornecida gera corretamente o hash de commitment.")
    else:
        print("\n❌ FALHA: A seed em texto plano NÃO corresponde ao hash de commitment.")
        sys.exit(1)


def handle_generate_commitment(args):
    """Manipulador para o comando 'generate-commitment'."""
    print("--- Gerando Commitment a partir da Seed ---")
    try:
        with open(args.metadata_file, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Erro ao ler o arquivo de metadados: {e}", file=sys.stderr)
        sys.exit(1)

    generated_hash = crypto_utils.compute_commitment_hash(args.seed, args.event_id, metadata)

    print(f"   ID do Evento: {args.event_id}")
    print(f"   Seed: {args.seed}")
    print(f"\n   Hash de Commitment Gerado: {generated_hash}")


def handle_verify_signature(args):
    """Manipulador para o comando 'verify-signature'."""
    print("--- Verificando Assinatura do Commitment ---")
    try:
        with open(args.public_key_file, 'r', encoding='utf-8') as f:
            public_key_pem = f.read()
    except FileNotFoundError:
        print(f"Erro: Arquivo de chave pública não encontrado em '{args.public_key_file}'", file=sys.stderr)
        sys.exit(1)

    is_valid = crypto_utils.verify_signature(public_key_pem, args.signature, args.committed_hash)

    print(f"   Hash de Commitment: {args.committed_hash}")
    print(f"   Assinatura:         {args.signature[:32]}...")
    print(f"   Arquivo de Chave Pública: {args.public_key_file}")

    if is_valid:
        print("\n✅ SUCESSO: A assinatura é válida e foi assinada pela chave privada correspondente.")
    else:
        print("\n❌ FALHA: A assinatura NÃO é válida.")
        sys.exit(1)

def handle_verify_full_chain(args):
    """Manipulador para o comando 'verify-full-chain'."""
    print("--- Verificando a Cadeia Completa: Descriptografar, Re-hashear e Comparar ---")

    # 1. Obter Chave de Descriptografia
    decryption_key = args.decryption_key or os.environ.get("SEED_ENCRYPTION_KEY_HEX")
    if not decryption_key:
        print("Erro: Chave de descriptografia não fornecida. Use --decryption-key ou defina a variável de ambiente SEED_ENCRYPTION_KEY_HEX.", file=sys.stderr)
        sys.exit(1)

    # 2. Descriptografar a seed
    print("Passo 1: Descriptografando a seed...")
    plaintext_seed = crypto_utils.decrypt_seed(args.encrypted_seed, args.iv, args.auth_tag, decryption_key)
    if plaintext_seed is None:
        print("\n❌ FALHA NA VERIFICAÇÃO DA CADEIA: Não foi possível descriptografar a seed.", file=sys.stderr)
        sys.exit(1)
    print(f"   ...Descriptografia bem-sucedida. Seed em texto plano recuperada: {plaintext_seed}")

    # 3. Re-calcular o hash
    print("Passo 2: Re-calculando o hash de commitment...")
    try:
        with open(args.metadata_file, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Erro ao ler o arquivo de metadados: {e}", file=sys.stderr)
        sys.exit(1)

    if args.debug:
        pre_hash_string = crypto_utils.get_pre_hash_string(plaintext_seed, args.event_id, metadata)
        print(f"\n[DEBUG] String que está sendo hasheada:\n---\n{pre_hash_string}\n---\n")

    recomputed_hash = crypto_utils.compute_commitment_hash(plaintext_seed, args.event_id, metadata)
    print(f"   ...Hash re-calculado: {recomputed_hash}")

    # 4. Comparar com o hash de commitment original
    print("Passo 3: Comparando os hashes...")
    print(f"   Hash Re-calculado: {recomputed_hash}")
    print(f"   Hash Original:     {args.committed_hash}")

    if recomputed_hash == args.committed_hash:
        print("\n✅ SUCESSO: A cadeia completa é válida. A seed criptografada descriptografa e gera corretamente o hash de commitment original.")
    else:
        print("\n❌ FALHA: Divergência de hash. A seed descriptografada não gera o hash de commitment original.")
        sys.exit(1)