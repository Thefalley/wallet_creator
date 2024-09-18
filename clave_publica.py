import hashlib
import base58
import ecdsa

# Función para convertir clave privada WIF a formato hexadecimal
def wif_a_hex(wif_clave_privada):
    # Decodificar clave privada WIF
    clave_privada_decodificada = base58.b58decode(wif_clave_privada)
    
    # Verificar si la clave WIF es comprimida (último byte == 0x01)
    if clave_privada_decodificada[-5] == 0x01:
        # Eliminar el prefijo (primer byte), byte de compresión (último byte) y checksum (últimos 4 bytes)
        clave_privada_hex = clave_privada_decodificada[1:-5]  # Eliminar 1 byte de prefijo y 1 byte de compresión
        comprimida = True
    else:
        # Eliminar el prefijo y el checksum (solo si no es comprimida)
        clave_privada_hex = clave_privada_decodificada[1:-4]  # Eliminar prefijo y checksum
        comprimida = False

    # Convertir a hexadecimal
    return clave_privada_hex.hex(), comprimida

# Función para calcular la clave pública a partir de la clave privada
def clave_publica_desde_privada(clave_privada_hex, comprimida=False):
    # Convertir la clave privada desde hexadecimal a bytes
    clave_privada_bytes = bytes.fromhex(clave_privada_hex)

    # Usar la curva SECP256k1 (la utilizada en Bitcoin)
    sk = ecdsa.SigningKey.from_string(clave_privada_bytes, curve=ecdsa.SECP256k1)

    # Obtener la clave pública en formato comprimido
    clave_publica_bytes = sk.verifying_key.to_string()
    if comprimida:
        if clave_publica_bytes[32] % 2 == 0:
            clave_publica_comprimida = b'\x02' + clave_publica_bytes[:32]
        else:
            clave_publica_comprimida = b'\x03' + clave_publica_bytes[:32]
        return clave_publica_comprimida.hex()
    else:
        # Clave pública no comprimida
        clave_publica_no_comprimida = b'\x04' + clave_publica_bytes
        return clave_publica_no_comprimida.hex()

# Función para calcular la dirección P2SH-P2WPKH (SegWit) desde la clave pública
def direccion_p2sh_p2wpkh(clave_publica_hex):
    # Convertir la clave pública desde hexadecimal a bytes
    clave_publica_bytes = bytes.fromhex(clave_publica_hex)

    # SHA-256 de la clave pública
    sha256_hash = hashlib.sha256(clave_publica_bytes).digest()

    # RIPEMD-160 del resultado del SHA-256
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    hashed_public_key = ripemd160.digest()

    # Preparar para P2SH (P2WPKH)
    script_sig = b'\x00\x14' + hashed_public_key

    # SHA-256 del script
    sha256_script_sig = hashlib.sha256(script_sig).digest()

    # RIPEMD-160 del script SHA-256
    ripemd160_script = hashlib.new('ripemd160')
    ripemd160_script.update(sha256_script_sig)
    hashed_script_sig = ripemd160_script.digest()

    # Prefijo de red para P2SH (0x05)
    prefijo_red = b'\x05'
    prefixed_hash = prefijo_red + hashed_script_sig

    # Realizar el doble SHA-256 para obtener el checksum
    checksum = hashlib.sha256(hashlib.sha256(prefixed_hash).digest()).digest()[:4]

    # Agregar el checksum al hash prefijado
    direccion_binaria = prefixed_hash + checksum

    # Codificar en Base58 la dirección
    direccion = base58.b58encode(direccion_binaria).decode()

    return direccion

# Clave privada en formato WIF
clave_privada_wif = "L3445sidDrenJAHPA7nCDrYU5CbsBeYdnokGzRpMzSH2kMQKgJHN"

# Convertir clave privada WIF a hexadecimal
clave_privada_hex, comprimida = wif_a_hex(clave_privada_wif)
print(f"Clave privada (hex): {clave_privada_hex}")

# Calcular la clave pública a partir de la clave privada
clave_publica = clave_publica_desde_privada(clave_privada_hex, comprimida=comprimida)
print(f"Clave pública (hex): {clave_publica}")

# Calcular la dirección P2SH-P2WPKH (SegWit) a partir de la clave pública
direccion = direccion_p2sh_p2wpkh(clave_publica)
print(f"Dirección de Bitcoin (SegWit P2SH-P2WPKH): {direccion}")
