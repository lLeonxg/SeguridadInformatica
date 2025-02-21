# firma digital usando RSA
# 2025-02-19
#LEONARDO XICOTENCATL ANAHAUC MAYAB

#importamos las librerias
import Crypto.Util.number
import hashlib

#Para usaremos el numero 4 de fermat
e = 65537

#calculamos las llave de alice 
pA = Crypto.Util.number.getPrime(1024, randfunc = Crypto.Random.get_random_bytes)
qA = Crypto.Util.number.getPrime(1024, randfunc = Crypto.Random.get_random_bytes)

nA = pA * qA
print("\n", "RSA alice: ", nA)

#calculamos la llave de bob
pB = Crypto.Util.number.getPrime(1024, randfunc = Crypto.Random.get_random_bytes)
qB = Crypto.Util.number.getPrime(1024, randfunc = Crypto.Random.get_random_bytes)

nB= pB * qB
print("\n", "RSA Bob: ", nB)


#calcualmos la llave privada de alcie 
phiA = (pA - 1) * (qA - 1)

dA = Crypto.Util.number.inverse(e,phiA)
print("\n", "RSA  la llave privada de alice: ", dA)

#calcualmos la llave privada de Bob 
phiB = (pB - 1) * (qB - 1)

dB = Crypto.Util.number.inverse(e,phiB)
print("\n", "RSA  la llave privada de Bob: ", dB)

#firmamos el mensaje <<<<<<<<<<<<<<<<<<<
mensaje = "Hola mundo "
print("\n", "mensaje ", mensaje)


#Generamos el jash del mensaj e
hM = int.from_bytes(hashlib.sha256(mensaje.encode('utf-8')).digest(),byteorder='big')
print("\n", "Hash de hM ", hex(hM))


#firmamos el HASH usando la llave privada de alice y se lo enviamos a BOB
sA = pow(hM, dA,nA)
print("\n", "Firma  ", sA)

#Bob verifica la firma de alice  usando la llave publica de alice
hM1 = pow(sA,e,nA)
print("\n", "Hash de hM ", hex(hM1))


#verificamos 
print("\n", "firma valida", hM == hM1,"\n" )
