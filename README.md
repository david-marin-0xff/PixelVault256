\# PixelVault256

<img width="1024" height="1024" alt="logo" src="https://github.com/user-attachments/assets/9e6eb9b9-2062-487d-ab66-3ad72f19a73e" />


\*\*PixelVault256\*\* is a single-file GUI application for secure data hiding and encryption.



\### 🔐 Features

\- AES-128 / AES-256 encryption (AES-GCM) with password-derived keys (PBKDF2HMAC + salt)

\- Steganography options:

&nbsp; - \*\*Pixel Stego\*\* (LSB-based)

&nbsp; - \*\*Metadata Stego\*\* (PNG `tEXt` chunk)

\- "Save As" dialogs for outputs

\- Extraction mode (reads stego, decrypts)

\- SHA-256 hash utility (file or text)

\- Custom error popups for failed decryptions

\- Self-contained Windows `.exe` build (no prerequisites)



\### Usage

1\. Run `pixelvault256.exe` (no install needed)

2\. Choose your mode: \*\*Encrypt\*\*, \*\*Decrypt\*\*, or \*\*Hash\*\*

3\. Select stego method and files

4\. Enter password → done!



\### Build from source

```bash

pip install -r requirements.txt

pyinstaller --onefile --windowed pixelvault256.py



##  Download 

You can download the latest Windows executable here:

[Download PixelVault256.exe (latest release)](https://github.com/david-marin-0xff/PixelVault256/releases/latest/download/pixelvault256.exe)
