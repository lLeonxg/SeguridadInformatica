import random
import hashlib

# Número primo de RFC3526 (1536 bits - MODP group)
p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)
g = 2

# Inicio
print("\n************************")
print("\nVariables públicas compartidas")
print("\nNúmero primo compartido públicamente RFC3526:", p)
print("\nNúmero base g compartido públicamente:", g)

# Generamos los números secretos de Alice, Bob y Eve
sAlice = random.getrandbits(256) # Número secreto de Alice
sBob = random.getrandbits(256)   # Número secreto de Bob
sEve = random.getrandbits(256)   # Número secreto de Eve

print("\nNúmero secreto de Alice:", sAlice)
print("\nNúmero secreto de Bob:", sBob)
print("\nNúmero secreto de Eve (atacante):", sEve)

# Alice envía A = g^a mod p a Bob
A = pow(g, sAlice, p)
print("\nMensaje de Alice a Bob (A):", A)

# Bob envía B = g^b mod p a Alice
B = pow(g, sBob, p)
print("\nMensaje de Bob a Alice (B):", B)

# Eve intercepta y calcula las llaves compartidas con Alice y Bob
sEveAlice = pow(A, sEve, p)  # Llave entre Alice y Eve
sEveBob = pow(B, sEve, p)    # Llave entre Bob y Eve

# Alice calcula la llave compartida con Bob
sAliceBob = pow(B, sAlice, p)

# Bob calcula la llave compartida con Alice
sBobAlice = pow(A, sBob, p)

# Aplicar función hash a las llaves
hAliceBob = hashlib.sha512(int.to_bytes(sAliceBob, length=1024, byteorder='big')).hexdigest()
hBobAlice = hashlib.sha512(int.to_bytes(sBobAlice, length=1024, byteorder='big')).hexdigest()
hEveAlice = hashlib.sha512(int.to_bytes(sEveAlice, length=1024, byteorder='big')).hexdigest()
hEveBob = hashlib.sha512(int.to_bytes(sEveBob, length=1024, byteorder='big')).hexdigest()

# Verificamos si las llaves coinciden
print("\nVerificación de llaves compartidas:")
print("\n¿Llave de Alice y Bob son iguales?", hAliceBob == hBobAlice)
print("\n¿Llave de Alice y Eve son iguales?", hAliceBob == hEveAlice)
print("\n¿Llave de Bob y Eve son iguales?", hBobAlice == hEveBob)
