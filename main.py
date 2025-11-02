from des.des_core import des_encrypt, des_decrypt
from des.utils import is_valid_hex

def main():
    plaintext = input("Enter plaintext (16 hex chars): ").strip().upper()
    key = input("Enter key (16 hex chars): ").strip().upper()

    if not is_valid_hex(plaintext, 16):
        print("Invalid plaintext format.")
        return
    if not is_valid_hex(key, 16):
        print("Invalid key format.")
        return

    ciphertext = des_encrypt(plaintext, key)
    decrypted = des_decrypt(ciphertext, key)

    print(f"\nPlaintext :  {plaintext}")
    print(f"Key       :  {key}")
    print(f"Ciphertext:  {ciphertext}")
    print(f"Decrypted :  {decrypted}")

    # Test vector
    print("\nStandard Test:")
    test_plain = "0123456789ABCDEF"
    test_key = "133457799BBCDFF1"
    test_cipher = des_encrypt(test_plain, test_key)
    test_decrypt = des_decrypt(test_cipher, test_key)
    print(f"Expected Cipher: 85E813540F0AB405")
    print(f"Ciphertext: {test_cipher}")
    print(f"Decrypted : {test_decrypt}")

if __name__ == "__main__":
    main()
