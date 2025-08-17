import hashlib
import json
import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag

def stable_stringify(data):
    """
    Cria uma string JSON consistente e ordenada a partir de um dicionário.
    Isso é crucial para garantir que o hash seja determinístico.
    """
    if not data:
        return ""
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def get_pre_hash_string(seed_hex, event_id, metadata):
    """Constrói a string que será hasheada, para fins de depuração."""
    metadata_str = stable_stringify(metadata)
    return f"{seed_hex}|{event_id}|{metadata_str}"

def compute_commitment_hash(seed_hex, event_id, metadata):
    """
    Calcula o hash SHA-256 para um commitment, replicando a lógica do TypeScript.
    Args:
        seed_hex (str): A seed secreta, codificada em hexadecimal.
        event_id (str): O identificador único para o evento.
        metadata (dict): Um dicionário de metadados associados ao evento.
    Retorna:
        str: O hash de commitment resultante, codificado em hexadecimal.
    """
    data_to_hash = get_pre_hash_string(seed_hex, event_id, metadata)
    hasher = hashlib.sha256()
    hasher.update(data_to_hash.encode('utf-8'))
    return hasher.hexdigest()

def verify_signature(public_key_pem, signature_hex, committed_hash_hex):
    """
    Verifica uma assinatura ECDSA de um determinado hash.
    Args:
        public_key_pem (str): A chave pública codificada em PEM.
        signature_hex (str): A assinatura, codificada em hexadecimal.
        committed_hash_hex (str): O hash que foi assinado, codificado em hexadecimal.
    Retorna:
        bool: True se a assinatura for válida, False caso contrário.
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        signature_bytes = bytes.fromhex(signature_hex)
        hash_bytes = bytes.fromhex(committed_hash_hex)

        # Para ECDSA, o algoritmo de assinatura é determinado pelo tipo de chave.
        # Os dados pré-hasheados (hash_bytes) são verificados contra a assinatura.
        public_key.verify(
            signature_bytes,
            hash_bytes,
            ec.ECDSA(hashes.SHA256()) # Isso assume que a chave é uma chave EC e o hash é SHA256
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Ocorreu um erro durante a verificação da assinatura: {e}", file=sys.stderr)
        return False

def decrypt_seed(encrypted_hex, iv_hex, auth_tag_hex, key_hex):
    """
    Descriptografa uma seed criptografada com AES-256-GCM.
    Esta função espelha a lógica `decryptData` do crypto do Node.js.
    """
    try:
        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex)
        auth_tag = bytes.fromhex(auth_tag_hex)
        ciphertext = bytes.fromhex(encrypted_hex)

        # No AESGCM do Python, a auth_tag é anexada ao ciphertext para a descriptografia.
        ciphertext_with_tag = ciphertext + auth_tag

        aesgcm = AESGCM(key)
        plaintext_bytes = aesgcm.decrypt(iv, ciphertext_with_tag, None)
        return plaintext_bytes.decode('utf-8')
    except InvalidTag:
        print("Falha na descriptografia: A tag de autenticação é inválida. Os dados podem ter sido adulterados ou a chave está incorreta.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Ocorreu um erro inesperado durante a descriptografia: {e}", file=sys.stderr)
        return None