from PIL import Image
import os

XOR_KEY_CONSTANT = 123  # Constant for XOR operation

def validate_image_path(image_path):
    """Checks if the given path points to a valid image file."""
    if not os.path.exists(image_path):
        print(f"Error: File not found at '{image_path}'")
        return False
    try:
        Image.open(image_path).verify() 
        return True
    except Exception:
        print(f"Error: '{image_path}' is not a valid image file.")
        return False

def get_pixel_data(image_path):
    """Loads an image and returns its pixel data."""
    img = Image.open(image_path)
    # Ensure image is in RGB format
    if img.mode != 'RGB':
        img = img.convert('RGB')
    return img, img.load() #pixel access object

def save_image(image_object, output_path):
    """Saves an Image object to the specified path."""
    try:
        image_object.save(output_path)
        print(f"Image saved successfully to '{output_path}'")
    except Exception as e:
        print(f"Error saving image to '{output_path}': {e}")

def encrypt_image_xor(image_path, output_path, key):
    """Encrypts an image using a simple XOR operation on pixel values."""
    print(f"Encrypting '{image_path}' using XOR with key '{key}'...")
    if not validate_image_path(image_path):
        return

    original_img, pixels = get_pixel_data(image_path)
    width, height = original_img.size

    encrypted_img = Image.new('RGB', (width, height))
    encrypted_pixels = encrypted_img.load()

    for x in range(width):
        for y in range(height):
            r, g, b = pixels[x, y]
            encrypted_pixels[x, y] = (r ^ (key % 256), g ^ (key % 256), b ^ (key % 256))

    save_image(encrypted_img, output_path)
    print("XOR encryption complete.")


def encrypt_image_pixel_shuffle(image_path, output_path, key):
    """
    Encrypts an image by shuffling pixels (simple row/column swap based on key).
    This is a very basic shuffle. More complex shuffles would involve permutations.
    """
    print(f"Encrypting '{image_path}' using pixel shuffling with key '{key}'...")
    if not validate_image_path(image_path):
        return

    original_img, pixels = get_pixel_data(image_path)
    width, height = original_img.size

    shuffled_img = Image.new('RGB', (width, height))
    shuffled_pixels = shuffled_img.load()
    shift_amount_rows = key % height
    shift_amount_cols = key % width

    for y in range(height):
        for x in range(width):
            new_y = (y + shift_amount_rows) % height
            new_x = (x + shift_amount_cols) % width
            shuffled_pixels[new_x, new_y] = pixels[x, y]

    save_image(shuffled_img, output_path)
    print("Pixel shuffling encryption complete.")


#Decryption

def decrypt_image_xor(image_path, output_path, key):
    """Decrypts an image encrypted with XOR."""
    print(f"Decrypting '{image_path}' using XOR with key '{key}'...")
    if not validate_image_path(image_path):
        return

    encrypted_img, pixels = get_pixel_data(image_path)
    width, height = encrypted_img.size

    decrypted_img = Image.new('RGB', (width, height))
    decrypted_pixels = decrypted_img.load()

    for x in range(width):
        for y in range(height):
            r, g, b = pixels[x, y]
            # Apply XOR again
            decrypted_pixels[x, y] = (r ^ (key % 256), g ^ (key % 256), b ^ (key % 256))

    save_image(decrypted_img, output_path)
    print("XOR decryption complete.")


def decrypt_image_pixel_shuffle(image_path, output_path, key):
    """
    Decrypts an image encrypted with pixel shuffling.
    This is the inverse of the simple row/column shift.
    """
    print(f"Decrypting '{image_path}' using pixel shuffling with key '{key}'...")
    if not validate_image_path(image_path):
        return

    shuffled_img, pixels = get_pixel_data(image_path)
    width, height = shuffled_img.size

    original_img = Image.new('RGB', (width, height))
    original_pixels = original_img.load()

    shift_amount_rows = key % height
    shift_amount_cols = key % width

    for y in range(height):
        for x in range(width):
            original_y = (y - shift_amount_rows + height) % height
            original_x = (x - shift_amount_cols + width) % width
            original_pixels[original_x, original_y] = pixels[x, y]

    save_image(original_img, output_path)
    print("Pixel shuffling decryption complete.")

def run_cli_tool():
    """Provides a simple command-line interface for the tool."""
    print("\nSimple Image Encryption/Decryption Tool")
    while True:
        print("\nChoose an option:")
        print("1. Encrypt Image (XOR)")
        print("2. Decrypt Image (XOR)")
        print("3. Encrypt Image (Pixel Shuffle)")
        print("4. Decrypt Image (Pixel Shuffle)")
        print("5. Exit")

        choice = input("Enter your choice (1-5): ")

        if choice == '5':
            print("Exiting tool")
            break

        image_path = input("Enter the path to the image file: ")
        output_path = input("Enter the desired output path for the processed image: ")
        key_input = input("Enter a numeric key (e.g., 123): ")

        try:
            key = int(key_input)
        except ValueError:
            print("Invalid key. Please enter a numeric value.")
            continue

        if choice == '1':
            encrypt_image_xor(image_path, output_path, key)
        elif choice == '2':
            decrypt_image_xor(image_path, output_path, key)
        elif choice == '3':
            encrypt_image_pixel_shuffle(image_path, output_path, key)
        elif choice == '4':
            decrypt_image_pixel_shuffle(image_path, output_path, key)
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    run_cli_tool()