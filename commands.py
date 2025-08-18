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

def handle_replicate_winners(args):
    """
    Executa a lógica de replicação de vencedores de forma determinística.
    """
    print("--- Replicando o Resultado do Sorteio ---")

    sorteio_details = None

    # Passo 1: Obter os detalhes do sorteio (de arquivo ou de argumentos)
    print("Passo 1: Carregando e validando os detalhes do sorteio...")

    if args.sorteio_details_file:
        try:
            with open(args.sorteio_details_file, 'r', encoding='utf-8') as f:
                sorteio_details = json.load(f)
            print(f"   ...Detalhes carregados do arquivo: '{args.sorteio_details_file}'")
        except FileNotFoundError:
            print(f"Erro: O arquivo de detalhes do sorteio '{args.sorteio_details_file}' não foi encontrado.", file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"Erro: O arquivo '{args.sorteio_details_file}' não contém um JSON válido.", file=sys.stderr)
            sys.exit(1)
    elif args.quantidade_numeros is not None and args.premio is not None:
        print("   ...Detalhes carregados dos argumentos da linha de comando.")
        try:
            premios_list = []
            for premio_str in args.premio:
                premio_obj = json.loads(premio_str)
                if not isinstance(premio_obj, dict):
                    raise TypeError(f"Cada prêmio deve ser um objeto JSON, mas foi recebido: {premio_str}")
                premios_list.append(premio_obj)
            
            sorteio_details = {
                "quantidadeNumeros": args.quantidade_numeros,
                "premios": premios_list
            }
        except json.JSONDecodeError as e:
            print(f"Erro: A string de prêmio fornecida não é um JSON válido: {e}", file=sys.stderr)
            sys.exit(1)
        except TypeError as e:
            print(f"Erro: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Erro: Você deve fornecer os detalhes do sorteio.", file=sys.stderr)
        print("   Use '--sorteio-details-file' OU use '--quantidade-numeros' e '--premio' juntos.", file=sys.stderr)
        sys.exit(1)

    # Validação da estrutura dos dados
    if 'quantidadeNumeros' not in sorteio_details or 'premios' not in sorteio_details:
        print("Erro: Os detalhes do sorteio devem conter as chaves 'quantidadeNumeros' e 'premios'.", file=sys.stderr)
        sys.exit(1)
    
    quantidade_numeros = sorteio_details['quantidadeNumeros']
    premios = sorteio_details['premios']
    document_id = sorteio_details.get('documentId', 'N/A')
    print(f"   ...Detalhes validados para o Sorteio ID: {document_id}")

    # Passo 2: Inicializar o PRNG
    print(f"Passo 2: Inicializando o gerador de números (PRNG) com o seed fornecido...")
    prng = crypto_utils.create_deterministic_prng(args.seed)
    print(f"   ...PRNG inicializado com seed: {args.seed[:16]}...")

    # Passo 3: Preparar e embaralhar os dados
    print("Passo 3: Preparando e embaralhando participantes e prêmios...")
    participant_numbers = list(range(1, quantidade_numeros + 1))
    flat_prize_list = [
        {'documentId': p.get('documentId', 'N/A'), 'Nome': p.get('Nome', 'N/A')}
        for p in premios for _ in range(p.get('Quantidade', 0))
    ]
    print(f"   ...{len(participant_numbers)} participantes e {len(flat_prize_list)} prêmios totais preparados.")
    
    crypto_utils.shuffle(participant_numbers, prng)
    crypto_utils.shuffle(flat_prize_list, prng)
    print("   ...Listas de participantes e prêmios embaralhadas deterministicamente.")

    # Passo 4: Atribuir prêmios
    print("Passo 4: Atribuindo prêmios aos vencedores...")
    assigned_winnings = {}
    total_prizes_to_award = len(flat_prize_list)

    for i in range(total_prizes_to_award):
        if i >= len(participant_numbers):
            print(f"Aviso: Mais prêmios ({total_prizes_to_award}) do que participantes ({len(participant_numbers)}). Alguns prêmios não serão atribuídos.", file=sys.stderr)
            break
        
        winning_number = str(participant_numbers[i])
        prize_won = flat_prize_list[i]

        if winning_number not in assigned_winnings:
            assigned_winnings[winning_number] = []
        assigned_winnings[winning_number].append(prize_won)

    winners_generated_count = len(assigned_winnings)
    print(f"   ...{total_prizes_to_award} prêmios atribuídos a {winners_generated_count} vencedores únicos.")

    # Passo 5: Apresentar resultados
    print("Passo 5: Gerando o resultado final...")
    result_data = {
        'winnersGeneratedCount': winners_generated_count,
        'assignedWinnings': assigned_winnings
    }

    if args.output_file:
        try:
            with open(args.output_file, 'w', encoding='utf-8') as f:
                json.dump(result_data, f, indent=4, ensure_ascii=False)
            print(f"   ...Resultados salvos em '{args.output_file}'")
        except IOError as e:
            print(f"\n❌ FALHA: Erro ao salvar o arquivo de saída: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("\n--- Resultados da Replicação ---")
        print(json.dumps(result_data, indent=2, ensure_ascii=False))

    print("\n✅ SUCESSO: A replicação do sorteio foi concluída.")