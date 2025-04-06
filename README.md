# Enhanced LSB Steganography

A powerful Python-based steganography tool for hiding messages and files within images using the Least Significant Bit (LSB) technique.

## Features

- **Text Embedding**: Hide text messages within images
- **File Embedding**: Hide any file type within images
- **Enhanced Security**: Optional AES encryption for embedded data
- **Randomized Embedding**: Optional pseudo-random bit distribution for improved security
- **Capacity Calculation**: Determine maximum payload capacity for any image
- **High Quality Output**: Preserves image quality with minimal visual artifacts
- **File Extraction**: Recover hidden files with original filenames
- **Performance Metrics**: Includes PSNR (Peak Signal-to-Noise Ratio) calculation

## Requirements

- Python 3.6+
- Required packages:
  - numpy
  - Pillow (PIL)
  - pycryptodome

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/ichsanfachris/steganography.git
   cd steganography-LSB
   ```

2. Install dependencies:
   ```
   pip install numpy pillow pycryptodome
   ```

## Usage

### Command Line Interface

Run the script to use the interactive CLI:

```
python steganography.py
```

The program offers six options:
1. Embed text message into image
2. Embed file into image
3. Extract message from stego image
4. Extract file from stego image
5. Calculate image capacity
6. Exit

### As a Python Module

You can also import and use the `EnhancedSteganographyLSB` class in your Python projects:

```python
from steganography import EnhancedSteganographyLSB

# Initialize the steganography object
steg = EnhancedSteganographyLSB()

# Embed a message
result = steg.embed_message(
    cover_path="original.png", 
    message="Secret message", 
    output_path="stego.png",
    password="your_password",
    use_encryption=True,
    use_randomization=True
)

# Extract a message
result = steg.extract_message(
    stego_path="stego.png",
    password="your_password",
    is_encrypted=True,
    is_randomized=True
)

# Embed a file
result = steg.embed_file(
    cover_path="original.png",
    file_path="document.pdf",
    output_path="stego.png",
    password="your_password",
    use_encryption=True,
    use_randomization=True
)

# Extract a file
result = steg.extract_file(
    stego_path="stego.png",
    output_dir="./extracted/",
    password="your_password",
    is_encrypted=True,
    is_randomized=True
)
```

## How It Works

This steganography tool uses the Least Significant Bit (LSB) technique to hide information:

1. The LSB of each color channel in an image pixel is modified to store 1 bit of the message
2. Modifications to the LSB are visually imperceptible in most images
3. Optional AES encryption adds a layer of security
4. Optional randomized embedding distributes the message bits throughout the image

## Technical Details

- **Capacity**: Approximately 1/8 of the total pixels × channels (minus delimiter space)
- **Encryption**: AES-256 in CBC mode with PKCS7 padding
- **Delimiter**: Uses "END_OF_MESSAGE" marker to identify message termination
- **File Header**: Embedded files include metadata (filename and size)
- **Image Quality**: Minimal degradation, typically with PSNR values above 50 dB

## Best Practices

1. Use larger images for bigger payloads
2. PNG format is recommended (lossless compression)
3. Always use encryption and randomization for sensitive data
4. Remember your password - encrypted data cannot be recovered without it
5. Be aware that JPEG compression can destroy steganographic data

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
