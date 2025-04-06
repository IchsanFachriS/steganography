import numpy as np
from PIL import Image
import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import io
import math
import struct

class SteganographyLSB:
    def __init__(self):
        """Initialize steganography class with default parameters"""
        self.delimiter = "END_OF_MESSAGE"  # Delimiter to mark the end of message
        self.supported_modes = ['RGB', 'RGBA', 'L']  # Supported image modes
    
    def calculate_capacity(self, image):
        """Calculate the maximum capacity for hiding data in the image in bytes"""
        width, height = image.size
        mode = image.mode
        
        if mode == 'RGB':
            channels = 3
        elif mode == 'RGBA':
            channels = 4
        elif mode == 'L':  # Grayscale
            channels = 1
        else:
            raise ValueError(f"Unsupported image mode: {mode}")
        
        # We use all channels and each pixel can store 1 bit per color channel
        total_bits = width * height * channels
        # Convert to bytes (8 bits per byte)
        total_bytes = total_bits // 8
        
        # Reserve space for the delimiter
        delimiter_bytes = len(self.delimiter) + 4  # +4 for length storage
        
        return total_bytes - delimiter_bytes
    
    def text_to_binary(self, text):
        """Convert text to binary string"""
        if isinstance(text, str):
            return ''.join(format(ord(char), '08b') for char in text)
        else:  # Assume it's bytes already
            return ''.join(format(byte, '08b') for byte in text)
    
    def binary_to_text(self, binary):
        """Convert binary string to text"""
        # Convert every 8 bits to a character
        text = bytearray()
        for i in range(0, len(binary), 8):
            byte = binary[i:i+8]
            if len(byte) == 8:  # Make sure we have 8 bits
                text.append(int(byte, 2))
        return text
    
    def encrypt_message(self, message, password):
        """Encrypt message with AES using the password"""
        # Generate a key from the password
        key = hashlib.sha256(password.encode()).digest()
        
        # Convert message to bytes if it's a string
        if isinstance(message, str):
            message = message.encode()
        
        # Create cipher and encrypt
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message, AES.block_size))
        
        # Store IV at the beginning of the encrypted message
        encrypted = cipher.iv + ct_bytes
        return encrypted
    
    def decrypt_message(self, encrypted, password):
        """Decrypt message with AES using the password"""
        # Generate key from password
        key = hashlib.sha256(password.encode()).digest()
        
        # Ensure we have enough data for IV
        if len(encrypted) < 16:
            print(f"Encrypted data too short: {len(encrypted)} bytes")
            return None
            
        # Extract IV from the beginning
        iv = encrypted[:16]
        ct_bytes = encrypted[16:]
        
        # Create cipher and decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
            return pt
        except Exception as e:
            print(f"Decryption error: {e}")
            return None  # Decryption failed
    
    def embed_message(self, cover_path, message, output_path, password=None, use_encryption=False):
        """Embed message into cover image with optional encryption"""
        # Read the cover image
        try:
            image = Image.open(cover_path)
        except Exception as e:
            raise ValueError(f"Error opening cover image: {e}")
        
        # Check image mode
        if image.mode not in self.supported_modes:
            raise ValueError(f"Unsupported image mode: {image.mode}. Supported modes: {self.supported_modes}")
        
        # Convert image to RGB if it's grayscale
        if image.mode == 'L':
            image = image.convert('RGB')
        
        # Get image dimensions and prepare pixel array
        width, height = image.size
        pixel_array = np.array(image)
        
        # Calculate total pixels and capacity
        max_capacity = self.calculate_capacity(image)
        
        # Process message
        if isinstance(message, str):
            message = message.encode()
        
        # Add delimiter
        final_message = message + self.delimiter.encode()
        
        # Encrypt if needed
        if use_encryption and password:
            final_message = self.encrypt_message(final_message, password)
        
        # Add length header (4 bytes for message length)
        length_header = struct.pack(">I", len(final_message))
        final_message_with_header = length_header + final_message
        
        # Check if message fits in the image
        if len(final_message_with_header) > max_capacity:
            raise ValueError(f"Message is too large for this image. Maximum capacity: {max_capacity} bytes, Message size: {len(final_message_with_header)} bytes")
        
        # Convert message to binary
        binary_message = self.text_to_binary(final_message_with_header)
        message_bits = len(binary_message)
        
        # Prepare for embedding
        flattened_array = pixel_array.reshape(-1)  # Flatten the array
        
        # Embed message bits sequentially
        for idx, bit in enumerate(binary_message):
            if idx < message_bits:
                # Change LSB
                byte_value = flattened_array[idx]
                flattened_array[idx] = (byte_value & ~1) | int(bit)
        
        # Reshape array back to image dimensions
        stego_array = flattened_array.reshape(pixel_array.shape)
        
        # Create and save stego image
        stego_image = Image.fromarray(stego_array)
        stego_image.save(output_path)
        
        # Calculate and return PSNR
        psnr = self.calculate_psnr(np.array(image), stego_array)
        
        return {
            "status": "success",
            "output_path": output_path,
            "message_size": len(final_message_with_header),
            "capacity_used": f"{len(final_message_with_header)/max_capacity*100:.2f}%",
            "psnr": f"{psnr:.2f} dB"
        }
    
    def embed_file(self, cover_path, file_path, output_path, password=None, use_encryption=False):
        """Embed a file into cover image"""
        # Read file as binary
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Add the file name and size to the data
        file_name = os.path.basename(file_path).encode()
        file_header = len(file_name).to_bytes(4, byteorder='big') + file_name + len(file_data).to_bytes(4, byteorder='big')
        
        # Combine header and file data
        message = file_header + file_data
        
        # Use the embed_message function
        return self.embed_message(cover_path, message, output_path, password, use_encryption)
    
    def extract_message(self, stego_path, password=None, is_encrypted=False):
        """Extract message from stego image"""
        # Read the stego image
        try:
            image = Image.open(stego_path)
        except Exception as e:
            raise ValueError(f"Error opening stego image: {e}")
        
        # Check image mode
        if image.mode not in self.supported_modes:
            raise ValueError(f"Unsupported image mode: {image.mode}")
        
        # Convert image to numpy array
        pixel_array = np.array(image)
        
        # Flatten the array
        flattened_array = pixel_array.reshape(-1)
        total_elements = len(flattened_array)
        
        # First extract the length header (first 32 bits / 4 bytes)
        binary_length_header = ""
        for i in range(32):
            if i < total_elements:
                binary_length_header += str(flattened_array[i] & 1)
        
        # Convert binary length header to integer
        length_bytes = self.binary_to_text(binary_length_header)
        message_length = struct.unpack(">I", length_bytes)[0]
        
        print(f"Extracted message length: {message_length} bytes")
        
        # Calculate total bits to extract (length header + message)
        total_bits_to_extract = 32 + (message_length * 8)
        
        # Extract all bits needed
        binary_message = binary_length_header  # Start with length header we already extracted
        for i in range(32, total_bits_to_extract):
            if i < total_elements:
                binary_message += str(flattened_array[i] & 1)
            else:
                print(f"Warning: Reached end of image data at bit {i}, needed {total_bits_to_extract}")
                break
        
        # Convert binary string to bytes
        extracted_bytes = self.binary_to_text(binary_message)
        
        # Skip the 4-byte length header to get actual message
        message_data = extracted_bytes[4:]
        
        # Verify we got the right number of bytes
        if len(message_data) != message_length:
            print(f"Warning: Extracted {len(message_data)} bytes, expected {message_length}")
        
        # Handle decryption if needed
        if is_encrypted and password:
            decrypted_data = self.decrypt_message(message_data, password)
            if decrypted_data is None:
                raise ValueError("Decryption failed. Incorrect password or corrupted data.")
            message_data = decrypted_data
        
        # Find delimiter in the extracted data
        try:
            delim_index = message_data.find(self.delimiter.encode())
            if delim_index != -1:
                message_data = message_data[:delim_index]
            else:
                # If delimiter not found, this may not be a valid steganography file
                print(f"Warning: Delimiter not found in extracted data ({len(message_data)} bytes)")
                return {"status": "warning", "message": "No valid message found or incorrect parameters."}
        except Exception as e:
            print(f"Error finding delimiter: {e}")
            return {"status": "error", "message": "Error processing extracted data."}
        
        # Try to interpret as text
        try:
            extracted_text = message_data.decode('utf-8')
            return {
                "status": "success", 
                "message_type": "text",
                "message": extracted_text,
                "binary": message_data
            }
        except UnicodeDecodeError:
            # Not valid text, might be binary file
            return {
                "status": "success", 
                "message_type": "binary",
                "message": "[Binary data]",
                "binary": message_data
            }
    
    def extract_file(self, stego_path, output_dir, password=None, is_encrypted=False):
        """Extract a file from stego image"""
        # Extract the raw data
        result = self.extract_message(stego_path, password, is_encrypted)
        
        if result["status"] != "success":
            return result
        
        if result["message_type"] != "binary":
            return {"status": "error", "message": "Extracted data is not a file."}
        
        # Parse the file header
        try:
            data = result["binary"]
            filename_length = int.from_bytes(data[:4], byteorder='big')
            filename = data[4:4+filename_length].decode('utf-8')
            file_size = int.from_bytes(data[4+filename_length:8+filename_length], byteorder='big')
            file_data = data[8+filename_length:8+filename_length+file_size]
            
            # Write the file
            output_path = os.path.join(output_dir, filename)
            with open(output_path, 'wb') as f:
                f.write(file_data)
            
            return {
                "status": "success",
                "message": f"File extracted successfully",
                "filename": filename,
                "output_path": output_path,
                "file_size": file_size
            }
        except Exception as e:
            return {"status": "error", "message": f"Error extracting file: {e}"}
    
    def calculate_psnr(self, original, modified):
        """Calculate Peak Signal-to-Noise Ratio between original and modified images"""
        mse = np.mean((original - modified) ** 2)
        if mse == 0:
            return float('inf')
        max_pixel = 255.0
        psnr = 20 * math.log10(max_pixel / math.sqrt(mse))
        return psnr

# Interactive CLI for the program
def main():
    steg = SteganographyLSB()
    
    print("===== LSB STEGANOGRAPHY PROGRAM =====")
    
    while True:
        print("\nSelect an operation:")
        print("1: Embed text message into image")
        print("2: Embed file into image")
        print("3: Extract message from stego image")
        print("4: Extract file from stego image")
        print("5: Calculate image capacity")
        print("6: Exit")
        
        choice = input("Enter your choice (1-6): ").strip()
        
        try:
            if choice == '1':  # Embed text
                cover_path = input("Enter cover image path: ").strip()
                message = input("Enter message to hide: ")
                output_path = input("Enter output stego image path: ").strip()
                
                use_encryption = input("Use encryption? (y/n): ").lower() == 'y'
                password = None
                if use_encryption:
                    password = input("Enter encryption password: ")
                
                result = steg.embed_message(
                    cover_path, message, output_path, 
                    password, use_encryption
                )
                
                print("\nEmbedding Results:")
                for key, value in result.items():
                    print(f"{key}: {value}")
                
            elif choice == '2':  # Embed file
                cover_path = input("Enter cover image path: ").strip()
                file_path = input("Enter file path to hide: ").strip()
                output_path = input("Enter output stego image path: ").strip()
                
                use_encryption = input("Use encryption? (y/n): ").lower() == 'y'
                password = None
                if use_encryption:
                    password = input("Enter encryption password: ")
                
                result = steg.embed_file(
                    cover_path, file_path, output_path,
                    password, use_encryption
                )
                
                print("\nFile Embedding Results:")
                for key, value in result.items():
                    print(f"{key}: {value}")
                
            elif choice == '3':  # Extract message
                stego_path = input("Enter stego image path: ").strip()
                
                is_encrypted = input("Is the message encrypted? (y/n): ").lower() == 'y'
                password = None
                if is_encrypted:
                    password = input("Enter decryption password: ")
                
                result = steg.extract_message(
                    stego_path, password, is_encrypted
                )
                
                print("\nExtraction Results:")
                if result["status"] == "success" and result["message_type"] == "text":
                    print(f"Extracted message: {result['message']}")
                else:
                    print(f"Status: {result['status']}")
                    print(f"Message: {result.get('message', 'Unknown error')}")
                
            elif choice == '4':  # Extract file
                stego_path = input("Enter stego image path: ").strip()
                output_dir = input("Enter directory to save extracted file: ").strip()
                
                is_encrypted = input("Is the file encrypted? (y/n): ").lower() == 'y'
                password = None
                if is_encrypted:
                    password = input("Enter decryption password: ")
                
                result = steg.extract_file(
                    stego_path, output_dir, password, is_encrypted
                )
                
                print("\nFile Extraction Results:")
                for key, value in result.items():
                    print(f"{key}: {value}")
                
            elif choice == '5':  # Calculate capacity
                image_path = input("Enter image path: ").strip()
                try:
                    image = Image.open(image_path)
                    capacity = steg.calculate_capacity(image)
                    print(f"\nMaximum capacity: {capacity} bytes ({capacity/1024:.2f} KB)")
                except Exception as e:
                    print(f"Error: {e}")
                    
            elif choice == '6':  # Exit
                print("Thank you for using the LSB Steganography Program!")
                break
                
            else:
                print("Invalid choice. Please try again.")
                
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()