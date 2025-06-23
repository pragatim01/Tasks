def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            # Shift character
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char  # Non-alphabet characters unchanged
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def main():
    print("=== Caesar Cipher Program ===")
    choice = input("Do you want to Encrypt (E) or Decrypt (D)? ").strip().upper()
    
    if choice not in ['E', 'D']:
        print("Invalid choice. Please choose E or D.")
        return
    
    message = input("Enter the message: ")
    try:
        shift = int(input("Enter the shift value (number): "))
    except ValueError:
        print("Shift must be a number.")
        return

    if choice == 'E':
        encrypted = caesar_encrypt(message, shift)
        print("Encrypted message:", encrypted)
    else:
        decrypted = caesar_decrypt(message, shift)
        print("Decrypted message:", decrypted)

if __name__ == "__main__":
    main()
