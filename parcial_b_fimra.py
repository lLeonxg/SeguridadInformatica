import Crypto.Util.number
import hashlib
import Crypto.Random


# Función para generar claves RSA de 2048 bits
def generar_claves_rsa():
    p = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
    q = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = Crypto.Util.number.inverse(65537, phi)  # Exponente fijo de Fermat (4° número)
    return (n, 65537, d)  # Retorna (n, e, d) -> (clave pública y privada)


# 1. Generamos claves RSA para Alice, AC y Bob
nA, eA, dA = generar_claves_rsa()  # Claves de Alice
nAC, eAC, dAC = generar_claves_rsa()  # Claves de la AC
nB, eB, dB = generar_claves_rsa()  # Claves de Bob

# 2. Leer el contenido del documento
ruta_documento = "NDA.pdf"  # Ruta del archivo a firmar
with open(ruta_documento, "rb") as file:
    documento = file.read()

# 3. Alice genera el hash SHA-256 del documento
hM = int.from_bytes(hashlib.sha256(documento).digest(), byteorder='big')
print("\n🔹 Hash SHA-256 del documento:", hex(hM))

# 4. Alice firma el hash con su clave privada
firmaAlice = pow(hM, dA, nA)
print("\n🔹 Firma digital de Alice:", hex(firmaAlice))

# 5. Guardar la firma en un archivo
with open("firmaAlice.txt", "w") as file:
    file.write(str(firmaAlice))

print("\n📤 Documento y firma enviados a la Autoridad Certificadora (AC).")

# 6. La AC verifica la firma de Alice
hM_verificado = pow(firmaAlice, eA, nA)

if hM_verificado == hM:
    print("\n✅ La AC confirma que la firma de Alice es válida.")

    # 7. La AC firma el documento con su clave privada
    firmaAC = pow(hM, dAC, nAC)
    print("\n🔹 La AC ha firmado el documento.")

    # 8. Guardar la firma de la AC en un archivo
    with open("firmaAC.txt", "w") as file:
        file.write(str(firmaAC))

    print("\n📤 La AC envía el documento firmado a Bob.")

    # 9. Bob verifica la firma de la AC
    hM_Bob = pow(firmaAC, eAC, nAC)

    if hM_Bob == hM:
        print("\n✅ La firma de la AC es válida. Bob confía en el documento.")
    else:
        print("\n❌ La firma de la AC es inválida. Bob no confía en el documento.")
else:
    print("\n❌ La AC detectó que la firma de Alice no es válida.")
