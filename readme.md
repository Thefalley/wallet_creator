Descripción del programa:
Clave privada WIF a hexadecimal:

Se convierte la clave privada de formato WIF a hexadecimal, eliminando el byte de compresión (si lo tiene) y el checksum.
Clave pública comprimida:

Se genera la clave pública comprimida desde la clave privada usando la curva elíptica SECP256k1, como lo exige Bitcoin.
Cálculo de la dirección SegWit (P2SH-P2WPKH):

La dirección que se genera es una dirección SegWit envolvente, la cual comienza con el prefijo 3, derivada a partir de la clave pública comprimida siguiendo el estándar BIP49.
Resultados esperados:
Cuando ejecutes este código, deberías obtener resultados similares a los que ves en la imagen, donde se muestra:

Clave privada en formato hexadecimal.
Clave pública comprimida en hexadecimal.
Dirección de Bitcoin (SegWit P2SH-P2WPKH) que comienza con 3.