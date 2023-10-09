from Crypto.PublicKey import RSA

def convert_hex_to_decimal(hex_string):
    try:
        decimal_value = int(hex_string, 16)
        return decimal_value
    except ValueError:
        print("Error: Invalid hexadecimal input.")
        return None

def get_modulus_and_bit_size_from_public_key_file(file_path):
    try:
        with open(file_path, 'rb') as key_file:
            public_key = RSA.import_key(key_file.read())
            modulus_hex = hex(public_key.n)[2:]  # Remove '0x' prefix
            modulus_decimal = convert_hex_to_decimal(modulus_hex)
            bit_size = public_key.size_in_bits()
            return modulus_decimal, bit_size
    except Exception as e:
        print("Error:", e)
        return None, None

if __name__ == "__main__":
    file_path = input("Enter the path to the .pem file: ")
    modulus, bit_size = get_modulus_and_bit_size_from_public_key_file(file_path)

    if modulus and bit_size:
        print("Modulus (Hex):", hex(modulus))
        print("Modulus (Decimal):", modulus)
        print("Bit Size:", bit_size)
