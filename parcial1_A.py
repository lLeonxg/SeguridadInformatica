from Crypto.Util import number
import hashlib

# 1. Definimos el exponente público (4to número de Fermat)
e = 65537

# 2. Generar primos aleatorios de 1024 bits para Alice
pA = number.getPrime(1024)
qA = number.getPrime(1024)
nA = pA * qA
phiA = (pA - 1) * (qA - 1)
dA = pow(e, -1, phiA)
print("Claves de Alice generadas.")
print(f"Clave pública de Alice (nA, e): ({nA}, {e})")
print(f"Clave privada de Alice (dA): {dA}")

# 3. Generar primos aleatorios de 1024 bits para Bob
pB = number.getPrime(1024)
qB = number.getPrime(1024)
nB = pB * qB
phiB = (pB - 1) * (qB - 1)
dB = pow(e, -1, phiB)
print("Claves de Bob generadas.")
print(f"Clave pública de Bob (nB, e): ({nB}, {e})")
print(f"Clave privada de Bob (dB): {dB}")

# 4. Mensaje original enviado por Alice (1050 caracteres)
mensaje = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Etiam finibus arcu eu neque scelerisque imperdiet. Ut a egestas orci. Vestibulum lacinia magna orci. Phasellus hendrerit neque est, sit amet malesuada purus porta ut. Sed rutrum odio sed turpis convallis, vel scelerisque justo hendrerit. Nulla facilisi. Praesent id sollicitudin dui. Fusce vel lectus vestibulum, consectetur justo blandit, aliquam nibh. Fusce placerat metus a turpis mattis rhoncus. Vestibulum vulputate quam eros, vitae egestas sapien feugiat eu. Nunc convallis porttitor fringilla. Duis blandit rutrum tortor eget convallis. Suspendisse malesuada arcu sit amet enim malesuada, id mollis tellus bibendum. Nulla nunc purus, auctor sed magna eu, hendrerit vulputate dui. Aliquam sagittis magna ac mi rhoncus bibendum. Nullam vitae rhoncus odio, vel cursus purus. Nam et risus vel nisi eleifend elementum."
print("Mensaje original de Alice preparado.")

# 5. Calcular hash del mensaje original
h_M = hashlib.sha256(mensaje.encode()).hexdigest()
print("Hash del mensaje original calculado por Alice: ", h_M)

# 6. Dividir en bloques de 128 caracteres
bloques = [mensaje[i:i+128] for i in range(0, len(mensaje), 128)]
print("Mensaje dividido en bloques de 128 caracteres.")

# 7. Alice cifra cada bloque con la clave pública de Bob
bloques_cifrados = [pow(int.from_bytes(b.encode(), 'big'), e, nB) for b in bloques]
print("Alice cifra los bloques con la clave pública de Bob.")
print("Bloques cifrados: ", bloques_cifrados)

# 8. Bob descifra cada bloque con su clave privada
bloques_descifrados = [pow(c, dB, nB).to_bytes((pow(c, dB, nB).bit_length() + 7) // 8, 'big').decode() for c in bloques_cifrados]
mensaje_recibido = "".join(bloques_descifrados)
print("Bob descifra los bloques con su clave privada.")
print("Mensaje descifrado: ", mensaje_recibido)

# 9. Calcular hash del mensaje recibido
h_M_prima = hashlib.sha256(mensaje_recibido.encode()).hexdigest()
print("Hash del mensaje recibido calculado por Bob: ", h_M_prima)

# 10. Comparar los hashes
print("\n¿El mensaje es auténtico?", h_M == h_M_prima)
