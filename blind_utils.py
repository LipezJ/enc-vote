from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, inverse
from Crypto.Random import get_random_bytes
import os
import json

# Cargar claves
def load_keys():
    with open('keys/private.pem', 'rb') as priv_file:
        priv_key = RSA.import_key(priv_file.read())
    with open('keys/public.pem', 'rb') as pub_file:
        pub_key = RSA.import_key(pub_file.read())
    return priv_key, pub_key

# 1. Generar nonce (16 bytes aleatorios)
def generate_nonce() -> bytes:
    return get_random_bytes(16)

# 2. Convertir candidato + nonce a entero (< N)
def message_to_int_with_nonce(candidate: str, nonce: bytes, pub_key: RSA.RsaKey) -> int:
    h_obj = SHA256.new()
    # Concatenamos texto del candidato y bytes del nonce
    h_obj.update(candidate.encode('utf-8'))
    h_obj.update(nonce)
    digest = h_obj.digest()
    return bytes_to_long(digest) % pub_key.n

# 3. Generar factor de cegado r coprimo con N
def generate_blinding_factor(pub_key: RSA.RsaKey) -> int:
    while True:
        # Generamos un número aleatorio de tamaño similar a N (en bytes)
        # y comprobamos si tiene inverso módulo N
        candidate = bytes_to_long(get_random_bytes(pub_key.size_in_bytes()))
        r = candidate % pub_key.n
        if r <= 1:
            continue
        try:
            inverse(r, pub_key.n)
            return r
        except ValueError:
            continue

# 4. Cegar mensaje: m' = m * r^e (mod N)
def blind_message(m: int, r: int, pub_key: RSA.RsaKey) -> int:
    return (m * pow(r, pub_key.e, pub_key.n)) % pub_key.n

# 5. Firma cegada: s' = (m')^d (mod N)
def sign_blinded(blinded: int, priv_key: RSA.RsaKey) -> int:
    return pow(blinded, priv_key.d, priv_key.n)

# 6. Destape: s = s' * r^{-1} (mod N)
def unblind_signature(s_blinded: int, r: int, pub_key: RSA.RsaKey) -> int:
    r_inv = inverse(r, pub_key.n)
    return (s_blinded * r_inv) % pub_key.n

# 7. Verificación: s^e mod N == m
def verify_signature(m: int, s: int, pub_key: RSA.RsaKey) -> bool:
    return pow(s, pub_key.e, pub_key.n) == m

# 8. Registrar voto en votes.json, incluyendo candidato y nonce
def record_vote(vote_entry: dict):
    """
    vote_entry debe ser un diccionario con llaves:
      'candidato'  -> str
      'nonce_hex'  -> str (hexadecimal)
      'm'          -> str (decimal)
      's'          -> str (decimal)
    """
    if not os.path.isfile('votes.json'):
        with open('votes.json', 'w') as f:
            json.dump([vote_entry], f, indent=4)
    else:
        with open('votes.json', 'r+') as f:
            data = json.load(f)
            data.append(vote_entry)
            f.seek(0)
            json.dump(data, f, indent=4)
