# **Ferramenta de Verificação do SM Prêmios LTDA**

Esta é uma ferramenta de linha de comando (CLI) desenvolvida em Python para verificar a integridade e a transparência dos sorteios, que utiliza um sistema de Geração de Números Aleatórios (RNG) baseado em um esquema de _commitment_ criptográfico.

Ela permite que qualquer pessoa verifique de forma independente se um resultado aleatório foi gerado de maneira justa, provando que a "semente" (o dado secreto) que gera o resultado corresponde ao _commitment_ (promessa) público divulgado antes do evento ocorrer.

## **Funcionalidades Principais**

- **Gerar Commitment:** Cria um hash de _commitment_ a partir de uma semente secreta e metadados públicos.
- **Verificar Correspondência:** Confirma se uma semente em texto plano corresponde a um hash de _commitment_ existente.
- **Verificar Assinatura Digital:** Valida se um _commitment_ foi assinado digitalmente por uma entidade confiável.
- **Verificar a Cadeia Completa:** Realiza o processo completo de ponta a ponta: descriptografa uma semente, recalcula o hash e o compara com o _commitment_ original, garantindo a integridade de todo o fluxo.

## **Estrutura do Projeto**

O projeto é organizado de forma modular para separar as responsabilidades e facilitar a manutenção:

```
sm_premios_script/
├── cli.py                 # Ponto de entrada principal, define a CLI com argparse
├── crypto_utils.py        # Funções puras de criptografia (hash, verificação, etc.)
├── commands.py            # Lógica de execução para cada comando da CLI
└── requirements.txt       # Lista de dependências do projeto
```

## **Instalação**

Para utilizar esta ferramenta, você precisará do Python 3.7+ instalado.

1. **Clone o repositório (ou crie os arquivos localmente):**

```
   # Se estivesse em um repositório git
   git clone https://github.com/BrenoLopesz/SM-Premios-CLI.git
   cd verificador_rng
```

2. **Crie um ambiente virtual (recomendado):**

```
   python -m venv venv
   source venv/bin/activate  # No Windows: venv\Scripts\activate
```

3. **Instale as dependências:**

```
   pip install -r requirements.txt
```

## **Como Usar**

A ferramenta é executada através do script `cli.py`, seguido por um dos comandos disponíveis.

### **Comandos Disponíveis**

#### **1. `generate-commitment`**

Gera um hash de _commitment_ a partir de uma semente e metadados. Útil para testes e simulações.

**Uso:**

```
python cli.py generate-commitment \
    --seed "uma_semente_secreta_em_hexadecimal_12345" \
    --event-id "sorteio-especial-2025" \
    --metadata-file "caminho/para/metadata.json"
```

#### **2. `check-match`**

Verifica se uma semente em texto plano (revelada após o evento) corresponde ao _commitment_ público.

**Uso:**

```
python cli.py check-match \
    --seed "semente_revelada_em_hex_abcde" \
    --event-id "sorteio-especial-2025" \
    --metadata-file "caminho/para/metadata.json" \
    --committed-hash "hash_publico_do_commitment_xyz"
```

#### **3. `verify-signature`**

Verifica se a assinatura digital do _commitment_ é válida, provando sua autenticidade.

**Uso:**

```
python cli.py verify-signature \
    --public-key-file "caminho/para/chave_publica.pem" \
    --signature "assinatura_em_hexadecimal_do_hash" \
    --committed-hash "hash_publico_do_commitment_xyz"
```

#### **4. `verify-full-chain`**

O comando mais completo. Ele descriptografa a semente, recalcula o hash e o compara com o _commitment_ original. Este é o principal teste de integridade para um observador externo.

**Uso:**

```
python cli.py verify-full-chain \
    --encrypted-seed "semente_criptografada_do_banco_de_dados" \
    --iv "vetor_de_inicializacao_hex" \
    --auth-tag "auth_tag_hex_do_aes_gcm" \
    --event-id "sorteio-especial-2025" \
    --metadata-file "caminho/para/metadata.json" \
    --committed-hash "hash_publico_do_commitment_xyz" \
    --decryption-key "chave_aes_para_descriptografar_a_semente"
```

#### **5. `replicate-winners`**

_O passo final da verificação de transparência_. Este comando usa a semente revelada e os detalhes do sorteio para reproduzir deterministicamente a lista exata de vencedores. Isso prova que o resultado não foi apenas derivado da semente correta, mas que o algoritmo de sorteio foi seguido fielmente.

**Uso (com arquivo de detalhes):**

```
python cli.py replicate-winners \
    --seed "semente_revelada_em_texto_plano" \
    --sorteio-details-file "caminho/para/detalhes_do_sorteio.json" \
    --output-file "resultado_replicado.json"
```

**Uso (com argumentos diretos):**
Para sorteios simples ou testes, você pode passar os detalhes diretamente.

```
python cli.py replicate-winners \
    --seed "semente_revelada_em_texto_plano" \
    --quantidade-numeros 1000 \
    --premio '{"documentId": "p-01", "Nome": "Prêmio A", "Quantidade": 1}' \
    --premio '{"documentId": "p-02", "Nome": "Prêmio B", "Quantidade": 5}'
```

**Nota de Segurança:**  
Para evitar expor a chave de descriptografia no histórico do seu terminal, é altamente recomendável defini-la como uma variável de ambiente. A ferramenta a detectará automaticamente.

**No Linux/macOS:**

```
export SEED_ENCRYPTION_KEY_HEX="sua_chave_aes_aqui"
```

**No Windows (PowerShell):**

```
$env:SEED_ENCRYPTION_KEY_HEX="sua_chave_aes_aqui"
```

Depois de definir a variável, você pode omitir o argumento `--decryption-key` do comando `verify-full-chain`.

## **Como o Processo Funciona**

1. **Commitment:** Antes de um evento aleatório, uma `semente` secreta é gerada. Um hash criptográfico (`commitment`) dessa semente, combinado com dados públicos (`metadata` e `event-id`), é calculado e publicado. Este hash é uma "promessa" de que a semente não será alterada.
2. **Assinatura:** O `commitment` é assinado digitalmente com uma chave privada, provando que foi gerado por uma entidade autêntica.
3. **Revelação:** Após o evento, a `semente` original é revelada.
4. **Verificação:** Qualquer pessoa pode usar esta ferramenta para:
   - Verificar se a assinatura do `commitment` é válida.
   - Recalcular o hash usando a semente revelada e os metadados.
   - Confirmar que o hash recalculado é idêntico ao `commitment` original.
   - Finalmente, **usar a mesma semente para replicar o resultado do sorteio**, garantindo que a lista de vencedores é a consequência direta e determinística da semente prometida.

Este processo garante que o resultado não foi manipulado, pois o `commitment` não pode ser alterado após sua publicação sem invalidar o hash.
