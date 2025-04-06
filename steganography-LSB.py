import numpy as np
from PIL import Image
import os
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import io
import math

class EnhancedSteganographyLSB:
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
    
    def generate_embedding_positions(self, seed, total_positions, message_length):
        """Generate pseudo-random positions for embedding using a seed"""
        random.seed(seed)
        positions = list(range(total_positions))
        random.shuffle(positions)
        return positions[:message_length * 8]
    
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
        
        # Extract IV from the beginning
        iv = encrypted[:16]
        ct_bytes = encrypted[16:]
        
        # Create cipher and decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        try:
            pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
            return pt
        except ValueError:
            return None  # Decryption failed
    
    def embed_message(self, cover_path, message, output_path, password=None, use_encryption=False, use_randomization=True):
        """Embed message into cover image with optional encryption and randomization"""
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
        
        # Process message: add delimiter and optionally encrypt
        if isinstance(message, str):
            message = message.encode() + self.delimiter.encode()
        else:  # Assume it's bytes already
            message = message + self.delimiter.encode()
        
        if use_encryption and password:
            message = self.encrypt_message(message, password)
        
        # Check if message fits in the image
        if len(message) > max_capacity:
            raise ValueError(f"Message is too large for this image. Maximum capacity: {max_capacity} bytes, Message size: {len(message)} bytes")
        
        # Convert message to binary
        binary_message = self.text_to_binary(message)
        message_bits = len(binary_message)
        
        # Prepare for embedding
        flattened_array = pixel_array.reshape(-1)  # Flatten the array
        total_elements = len(flattened_array)
        
        # Generate embedding positions
        if use_randomization and password:
            # Use password as seed for randomization
            seed = int(hashlib.md5(password.encode()).hexdigest(), 16) % 10000000
            positions = self.generate_embedding_positions(seed, total_elements, message_bits)
        else:
            positions = list(range(message_bits))
        
        # Embed message bits
        for idx, bit in enumerate(binary_message):
            if idx < message_bits:
                pos = positions[idx] if use_randomization and password else idx
                # Change LSB
                byte_value = flattened_array[pos]
                flattened_array[pos] = (byte_value & ~1) | int(bit)
        
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
            "message_size": len(message),
            "capacity_used": f"{len(message)/max_capacity*100:.2f}%",
            "psnr": f"{psnr:.2f} dB"
        }
    
    def embed_file(self, cover_path, file_path, output_path, password=None, use_encryption=False, use_randomization=True):
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
        return self.embed_message(cover_path, message, output_path, password, use_encryption, use_randomization)
    
    def extract_message(self, stego_path, password=None, is_encrypted=False, is_randomized=True):
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
        
        # Generate extraction positions
        if is_randomized and password:
            # Use same seed as in embedding
            seed = int(hashlib.md5(password.encode()).hexdigest(), 16) % 10000000
            # We don't know the message length yet, so use a large number
            positions = self.generate_embedding_positions(seed, total_elements, total_elements // 8)
        
        # Extract LSBs
        binary_message = ""
        max_bits = min(total_elements, 10000000)  # Limit to prevent excessive processing
        
        for i in range(max_bits):
            pos = positions[i] if is_randomized and password else i
            if pos < total_elements:
                binary_message += str(flattened_array[pos] & 1)
            
            # Every 8 bits, check for delimiter
            if i % 8 == 7 and i >= (len(self.delimiter) * 8):
                # Convert recent bits to text
                current_bytes = self.binary_to_text(binary_message[-len(self.delimiter)*8:])
                try:
                    current_text = current_bytes.decode('utf-8', errors='ignore')
                    # Check if we've reached the delimiter
                    if self.delimiter in current_text:
                        break
                except:
                    pass
        
        # Convert binary to bytes
        extracted_bytes = self.binary_to_text(binary_message)
        
        # Handle decryption if needed
        if is_encrypted and password:
            extracted_bytes = self.decrypt_message(extracted_bytes, password)
            if extracted_bytes is None:
                raise ValueError("Decryption failed. Incorrect password?")
        
        # Find delimiter
        try:
            delim_index = extracted_bytes.find(self.delimiter.encode())
            if delim_index != -1:
                extracted_bytes = extracted_bytes[:delim_index]
            else:
                # If delimiter not found, this may not be a valid steganography file
                return {"status": "warning", "message": "No valid message found or incorrect parameters."}
        except:
            return {"status": "error", "message": "Error processing extracted data."}
        
        # Try to interpret as text
        try:
            extracted_text = extracted_bytes.decode('utf-8')
            return {
                "status": "success", 
                "message_type": "text",
                "message": extracted_text,
                "binary": extracted_bytes
            }
        except UnicodeDecodeError:
            # Not valid text, might be binary file
            return {
                "status": "success", 
                "message_type": "binary",
                "message": "[Binary data]",
                "binary": extracted_bytes
            }
    
    def extract_file(self, stego_path, output_dir, password=None, is_encrypted=False, is_randomized=True):
        """Extract a file from stego image"""
        # Extract the raw data
        result = self.extract_message(stego_path, password, is_encrypted, is_randomized)
        
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
    steg = EnhancedSteganographyLSB()
    
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
                
                use_randomization = input("Use random bit embedding? (y/n): ").lower() == 'y'
                
                result = steg.embed_message(
                    cover_path, message, output_path, 
                    password, use_encryption, use_randomization
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
                
                use_randomization = input("Use random bit embedding? (y/n): ").lower() == 'y'
                
                result = steg.embed_file(
                    cover_path, file_path, output_path,
                    password, use_encryption, use_randomization
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
                
                is_randomized = input("Was random bit embedding used? (y/n): ").lower() == 'y'
                
                result = steg.extract_message(
                    stego_path, password, is_encrypted, is_randomized
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
                
                is_randomized = input("Was random bit embedding used? (y/n): ").lower() == 'y'
                
                result = steg.extract_file(
                    stego_path, output_dir, password, is_encrypted, is_randomized
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
                print("Thank you for using the Enhanced LSB Steganography Program!")
                break
                
            else:
                print("Invalid choice. Please try again.")
                
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
