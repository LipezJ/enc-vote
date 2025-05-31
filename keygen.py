from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, inverse
import os

# 1. Generar primos p y q de 1024 bits
p = getPrime(1024)
q = getPrime(1024)
N = p * q
phi = (p - 1) * (q - 1)

# 2. Elegir exponente público
e = 65537

# 3. Calcular exponente privado
d = inverse(e, phi)

# 4. Construir clave RSA
key = RSA.construct((N, e, d, p, q))

# 5. Exportar a archivos PEM
private_key = key.export_key(format='PEM')
public_key = key.publickey().export_key(format='PEM')

os.makedirs('keys', exist_ok=True)
with open('keys/private.pem', 'wb') as priv_file:
    priv_file.write(private_key)

with open('keys/public.pem', 'wb') as pub_file:
    pub_file.write(public_key)

print("Claves RSA generadas y almacenadas en 'keys/private.pem' y 'keys/public.pem'")
