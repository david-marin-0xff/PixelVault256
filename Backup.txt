"""
PixelVault256 - single-file GUI app
Features:
 - AES-128 / AES-256 encryption (AES-GCM) with password-derived keys (PBKDF2HMAC + salt)
 - Pixel Stego (LSB-based) and Metadata Stego (PNG tEXt chunk) selectable
 - Save As dialogs for outputs
 - Extract functionality (reads stego, decrypts)
 - SHA-256 hash utility (file or text)
 - Uses customtkinter + Pillow + cryptography
Author: david-marin-0xff
"""

import os
import base64
import struct
import hashlib
import secrets
from tkinter import filedialog, messagebox

import customtkinter as ctk
from PIL import Image, ImageTk, PngImagePlugin
import webbrowser

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# -----------------------
# Constants & utilities
# -----------------------
MAGIC = b"PVLT"   # 4 bytes magic header
VERSION = 1       # 1 byte version
SALT_SIZE = 16    # bytes for PBKDF2 salt
NONCE_SIZE = 12   # AESGCM nonce size
KDF_ITERS = 200_000

# pack header: MAGIC (4), ver (1), enc_type (1) 0x10=128 0x20=256, payload_len (4, unsigned)
# total header size = 10 bytes
HEADER_FMT = ">4sB B I"  # magic, version, enc_type, length
HEADER_SIZE = struct.calcsize(HEADER_FMT)

def derive_key(password: str, salt: bytes, key_len: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_len,
        salt=salt,
        iterations=KDF_ITERS,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_bytes(plaintext: bytes, password: str, key_bits: int) -> bytes:
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt, key_bits // 8)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # tag included
    # stored payload = salt || nonce || ciphertext
    return salt + nonce + ciphertext

def decrypt_bytes(payload: bytes, password: str, key_bits: int) -> bytes:
    if len(payload) < SALT_SIZE + NONCE_SIZE + 1:
        raise ValueError("Payload too small to be valid")
    salt = payload[:SALT_SIZE]
    nonce = payload[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = payload[SALT_SIZE + NONCE_SIZE:]
    key = derive_key(password, salt, key_bits // 8)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def bytes_to_base64_text(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def base64_text_to_bytes(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

# -----------------------
# LSB pixel stego helpers
# -----------------------
def embed_payload_in_image_lsb(input_image_path: str, payload: bytes, output_path: str) -> None:
    """
    Embed payload bytes into the image LSBs (RGB channels).
    We store a header with total payload length so extraction can stop.
    """
    img = Image.open(input_image_path)
    # Ensure we use RGB
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA")
    rgba = img.convert("RGBA")
    pixels = bytearray(rgba.tobytes())  # bytes in RGBA order
    channels = 4  # RGBA channels per pixel
    # We'll use only RGB channels (first 3) to avoid touching alpha
    usable_channels_per_pixel = 3
    total_pixels = len(pixels) // channels
    capacity_bits = total_pixels * usable_channels_per_pixel  # 1 LSB per RGB channel
    required_bits = (HEADER_SIZE + len(payload)) * 8
    if required_bits > capacity_bits:
        raise ValueError(f"Payload too large for image capacity. Need {required_bits} bits, capacity {capacity_bits} bits.")
    # Build data to embed = header + payload
    enc_type_flag = 0x10 if (selected_enc_val() == "AES-128") else 0x20
    header = struct.pack(HEADER_FMT, MAGIC, VERSION, enc_type_flag, len(payload))
    data = header + payload
    # Iterate bits and set LSBs
    bit_index = 0
    for i in range(0, len(pixels), channels):
        # for each pixel, write into R,G,B channels only
        for ch in range(usable_channels_per_pixel):
            if bit_index >= len(data) * 8:
                break
            byte_index = bit_index // 8
            bit_in_byte = 7 - (bit_index % 8)
            bit = (data[byte_index] >> bit_in_byte) & 1
            pixels[i + ch] = (pixels[i + ch] & 0xFE) | bit
            bit_index += 1
        if bit_index >= len(data) * 8:
            break
    # create new image from modified bytes
    new_img = Image.frombytes("RGBA", rgba.size, bytes(pixels))
    # If original image had no alpha, convert back to RGB to avoid adding transparency
    if img.mode == "RGB":
        new_img = new_img.convert("RGB")
    new_img.save(output_path)
    return

def extract_payload_from_image_lsb(input_image_path: str) -> bytes:
    img = Image.open(input_image_path)
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA")
    rgba = img.convert("RGBA")
    pixels = bytearray(rgba.tobytes())
    channels = 4
    usable_channels_per_pixel = 3
    # First extract header bits
    bits_needed_for_header = HEADER_SIZE * 8
    collected_bits = []
    bit_index = 0
    for i in range(0, len(pixels), channels):
        for ch in range(usable_channels_per_pixel):
            if bit_index < bits_needed_for_header:
                bit = pixels[i + ch] & 1
                collected_bits.append(bit)
                bit_index += 1
            else:
                break
        if bit_index >= bits_needed_for_header:
            break
    # bits -> header bytes
    header_bytes = bytearray()
    for b in range(0, bits_needed_for_header, 8):
        byte = 0
        for bitpos in range(8):
            byte = (byte << 1) | collected_bits[b + bitpos]
        header_bytes.append(byte)
    if len(header_bytes) != HEADER_SIZE:
        raise ValueError("Failed to read header from image.")
    magic, ver, enc_flag, payload_len = struct.unpack(HEADER_FMT, bytes(header_bytes))
    if magic != MAGIC:
        raise ValueError("No PixelVault payload (magic mismatch).")
    # now read payload_len bytes worth of bits
    total_bits_to_read = payload_len * 8
    collected_bits = []
    bit_index = 0
    # continue from where we left off (pixel index)
    # calculate start pixel index
    header_bits_consumed = bits_needed_for_header
    pixel_idx = header_bits_consumed // usable_channels_per_pixel
    channel_offset = header_bits_consumed % usable_channels_per_pixel
    flat_index = pixel_idx * channels  # byte index into pixels
    # iterate bits
    while len(collected_bits) < total_bits_to_read:
        # ensure flat_index within pixels
        if flat_index >= len(pixels):
            raise ValueError("Image does not contain entire payload.")
        for ch in range(channel_offset, usable_channels_per_pixel):
            if len(collected_bits) >= total_bits_to_read:
                break
            collected_bits.append(pixels[flat_index + ch] & 1)
        # move to next pixel
        flat_index += channels
        channel_offset = 0
    # bits -> bytes
    payload = bytearray()
    for b in range(0, total_bits_to_read, 8):
        byte = 0
        for bitpos in range(8):
            byte = (byte << 1) | collected_bits[b + bitpos]
        payload.append(byte)
    return bytes(payload)

# -----------------------
# Metadata stego helpers
# -----------------------
META_KEY = "PixelVault256"

def embed_payload_in_png_metadata(input_image_path: str, payload: bytes, output_path: str) -> None:
    """
    Store base64-encoded payload in PNG tEXt chunk under META_KEY.
    Only reliably works for PNGs.
    """
    img = Image.open(input_image_path)
    if img.format != "PNG":
        raise ValueError("Metadata stego currently supports only PNG images (tEXt chunks).")
    pnginfo = PngImagePlugin.PngInfo()
    encoded = bytes_to_base64_text(payload)
    pnginfo.add_text(META_KEY, encoded)
    # preserve existing chunks if possible
    img.save(output_path, "PNG", pnginfo=pnginfo)

def extract_payload_from_png_metadata(input_image_path: str) -> bytes:
    img = Image.open(input_image_path)
    if img.format != "PNG":
        raise ValueError("Metadata extraction only supported for PNG.")
    info = img.info
    if META_KEY not in info:
        raise ValueError("No PixelVault metadata found in PNG.")
    encoded = info[META_KEY]
    return base64_text_to_bytes(encoded)

# -----------------------
# GUI + wiring
# -----------------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("PixelVault256")
app.geometry("860x700")  # slightly larger default
app.minsize(760, 640)    # prevent it from getting too small
app.resizable(True, True)  # now supports maximize and resizing


# --- Load logo ---
try:
    logo_img = Image.open("logo.png").resize((120, 120))
    logo_photo = ImageTk.PhotoImage(logo_img)
except Exception as e:
    logo_photo = None
    print("Logo not found:", e)

# Header
header_frame = ctk.CTkFrame(app)
header_frame.pack(pady=10)
if logo_photo:
    ctk.CTkLabel(header_frame, image=logo_photo, text="").pack()
ctk.CTkLabel(header_frame, text="PixelVault256", font=ctk.CTkFont(size=28, weight="bold")).pack(pady=6)
ctk.CTkLabel(header_frame, text="by david-marin-0xff", text_color="gray").pack()

# Tabs
tabview = ctk.CTkTabview(app, width=720, height=470)
tabview.pack(pady=18)

stego_tab = tabview.add("Steganography")
hash_tab = tabview.add("Hash Utility")
about_tab = tabview.add("About")

# --- Steganography tab UI ---
ctk.CTkLabel(stego_tab, text="Embed / Extract Hidden Text", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=6)

# Encryption dropdown
ctk.CTkLabel(stego_tab, text="Encryption:").pack(pady=(6, 0))
enc_type_var = ctk.StringVar(value="AES-256")
enc_option = ctk.CTkOptionMenu(stego_tab, values=["AES-128", "AES-256"], variable=enc_type_var)
enc_option.pack(pady=6)

# Password entry
ctk.CTkLabel(stego_tab, text="Password:").pack(pady=(6, 0))
pwd_entry = ctk.CTkEntry(stego_tab, show="*")
pwd_entry.pack(pady=6)

# Stego mode
ctk.CTkLabel(stego_tab, text="Stego Mode:").pack(pady=(8, 0))
mode_var = ctk.StringVar(value="Pixel Stego (Hidden in pixels)")
mode_option = ctk.CTkOptionMenu(
    stego_tab,
    values=["Pixel Stego (Hidden in pixels)", "Metadata Stego (Stored in PNG metadata)"],
    variable=mode_var,
)
mode_option.pack(pady=6)

explanation_var = ctk.StringVar(value="Pixel Stego: hides data in pixel LSBs (harder to detect).")
explanation_label = ctk.CTkLabel(stego_tab, textvariable=explanation_var, wraplength=660, text_color="lightgray")
explanation_label.pack(pady=4)

def update_mode_explanation(choice):
    if "Pixel" in choice:
        explanation_var.set("Pixel Stego: True hidden data inside image pixels using least-significant-bit encoding. Harder to detect but depends on image capacity.")
    else:
        explanation_var.set("Metadata Stego: Stores encrypted payload in PNG metadata (tEXt chunk). Fast and simple, but only for PNG and easier to discover.")
mode_option.configure(command=update_mode_explanation)

# File selection
selected_text_path = ctk.StringVar(value="No text file selected")
selected_image_path = ctk.StringVar(value="No image file selected")

def select_text_file():
    p = filedialog.askopenfilename(title="Select Text File", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if p:
        selected_text_path.set(p)

def select_image_file():
    p = filedialog.askopenfilename(title="Select Image File", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp"), ("All Files", "*.*")])
    if p:
        selected_image_path.set(p)

file_frame = ctk.CTkFrame(stego_tab)
file_frame.pack(pady=6)
ctk.CTkButton(file_frame, text="Select Text File", command=select_text_file).grid(row=0, column=0, padx=8, pady=4)
ctk.CTkLabel(file_frame, textvariable=selected_text_path, width=70, anchor="w").grid(row=0, column=1, padx=8)
ctk.CTkButton(file_frame, text="Select Image File", command=select_image_file).grid(row=1, column=0, padx=8, pady=4)
ctk.CTkLabel(file_frame, textvariable=selected_image_path, width=70, anchor="w").grid(row=1, column=1, padx=8)

# Status
status_var = ctk.StringVar(value="")
status_label = ctk.CTkLabel(stego_tab, textvariable=status_var, text_color="lightgreen")
status_label.pack(pady=6)

# Actions
def selected_enc_val() -> str:
    return enc_type_var.get()

def selected_mode_val() -> str:
    return mode_var.get()

def on_embed():
    text_path = selected_text_path.get()
    img_path = selected_image_path.get()
    password = pwd_entry.get()
    if not text_path or text_path == "No text file selected":
        messagebox.showerror("Missing file", "Please select a text file to embed.")
        return
    if not img_path or img_path == "No image file selected":
        messagebox.showerror("Missing file", "Please select an image file to embed into.")
        return
    if not password:
        messagebox.showerror("Missing password", "Please enter a password.")
        return
    try:
        with open(text_path, "rb") as f:
            plaintext = f.read()
        # encrypt
        key_bits = 128 if selected_enc_val() == "AES-128" else 256
        payload = encrypt_bytes(plaintext, password, key_bits)
        # Choose mode
        mode = selected_mode_val()
        # Save As dialog
        if "Pixel" in mode:
            default_name = os.path.splitext(os.path.basename(img_path))[0] + "_stego.png"
            out_path = filedialog.asksaveasfilename(defaultextension=".png", initialfile=default_name, filetypes=[("PNG Image", "*.png")])
            if not out_path:
                status_var.set("Embed cancelled.")
                return
            embed_payload_in_image_lsb(img_path, payload, out_path)
        else:
            # metadata mode - only supports PNG
            if not img_path.lower().endswith(".png"):
                messagebox.showwarning("PNG recommended", "Metadata mode requires PNG. Consider converting the image to PNG first.")
            default_name = os.path.splitext(os.path.basename(img_path))[0] + "_meta_stego.png"
            out_path = filedialog.asksaveasfilename(defaultextension=".png", initialfile=default_name, filetypes=[("PNG Image", "*.png")])
            if not out_path:
                status_var.set("Embed cancelled.")
                return
            embed_payload_in_png_metadata(img_path, payload, out_path)
        status_var.set(f"Embed successful → {os.path.basename(out_path)}")
        messagebox.showinfo("Success", f"Embedded successfully and saved to:\n{out_path}")
    except Exception as e:
        status_var.set("Error during embed.")
        messagebox.showerror("Embed error", str(e))

def on_extract():
    img_path = selected_image_path.get()
    password = pwd_entry.get()
    if not img_path or img_path == "No image file selected":
        messagebox.showerror("Missing file", "Please select the image file to extract from (use Select Image File).")
        return
    if not password:
        messagebox.showerror("Missing password", "Please enter the password used during embedding.")
        return
    try:
        mode = selected_mode_val()
        if "Pixel" in mode:
            payload = extract_payload_from_image_lsb(img_path)
            # payload is the encrypted bytes
            # But LSB embed included only payload bytes (no salt? Actually encrypt_bytes produced salt+nonce+ciphertext)
            # decrypt needs key_bits matching chosen encryption
            key_bits = 128 if selected_enc_val() == "AES-128" else 256
            # Decrypt and save as Save As txt
            plaintext = decrypt_bytes(payload, password, key_bits)
            out_path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="output_extracted.txt", filetypes=[("Text File", "*.txt")])
            if not out_path:
                status_var.set("Extract cancelled.")
                return
            with open(out_path, "wb") as f:
                f.write(plaintext)
            status_var.set(f"Extracted and saved → {os.path.basename(out_path)}")
            messagebox.showinfo("Success", f"Extracted plaintext saved to:\n{out_path}")
        else:
            # metadata mode
            payload = extract_payload_from_png_metadata(img_path)
            key_bits = 128 if selected_enc_val() == "AES-128" else 256
            plaintext = decrypt_bytes(payload, password, key_bits)
            out_path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="output_extracted.txt", filetypes=[("Text File", "*.txt")])
            if not out_path:
                status_var.set("Extract cancelled.")
                return
            with open(out_path, "wb") as f:
                f.write(plaintext)
            status_var.set(f"Extracted and saved → {os.path.basename(out_path)}")
            messagebox.showinfo("Success", f"Extracted plaintext saved to:\n{out_path}")
    except Exception as e:
        status_var.set("Error during extract.")
        messagebox.showerror("Extract error", str(e))

embed_btn = ctk.CTkButton(stego_tab, text="🔒 Embed Text", command=on_embed)
embed_btn.pack(pady=(8, 6))
extract_btn = ctk.CTkButton(stego_tab, text="🔓 Extract Text", command=on_extract)
extract_btn.pack(pady=(2, 8))

# --- Hash Utility tab ---
ctk.CTkLabel(hash_tab, text="Hash Utility (SHA-256)", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=8)

hash_file_path = ctk.StringVar(value="No file selected")
hash_text_input = ctk.StringVar(value="")

def select_hash_file():
    p = filedialog.askopenfilename(title="Select File to Hash", filetypes=[("All files", "*.*")])
    if p:
        hash_file_path.set(p)

def compute_hash_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def compute_hash_of_text(s: str):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

# UI
filehash_frame = ctk.CTkFrame(hash_tab)
filehash_frame.pack(pady=6)
ctk.CTkButton(filehash_frame, text="Select File", command=select_hash_file).grid(row=0, column=0, padx=6)
ctk.CTkLabel(filehash_frame, textvariable=hash_file_path, anchor="w", width=60).grid(row=0, column=1, padx=6)

ctk.CTkLabel(hash_tab, text="Or paste text below and press Compute:").pack(pady=(10, 0))
text_entry = ctk.CTkTextbox(hash_tab, width=640, height=120)
text_entry.pack(pady=6)

hash_result_var = ctk.StringVar(value="Hash will appear here")

def on_compute_file_hash():
    p = hash_file_path.get()
    if not p or p == "No file selected":
        messagebox.showerror("No file", "Please select a file to hash.")
        return
    try:
        digest = compute_hash_of_file(p)
        hash_result_var.set(digest)
    except Exception as e:
        messagebox.showerror("Hash error", str(e))

def on_compute_text_hash():
    text = text_entry.get("0.0", "end").rstrip("\n")
    if not text:
        messagebox.showerror("No text", "Please paste or type text into the box first.")
        return
    digest = compute_hash_of_text(text)
    hash_result_var.set(digest)

ctk.CTkButton(hash_tab, text="Compute File SHA-256", command=on_compute_file_hash).pack(pady=6)
ctk.CTkButton(hash_tab, text="Compute Text SHA-256", command=on_compute_text_hash).pack(pady=4)
ctk.CTkLabel(hash_tab, textvariable=hash_result_var, wraplength=660).pack(pady=8)

def copy_hash_to_clipboard():
    app.clipboard_clear()
    app.clipboard_append(hash_result_var.get())
    messagebox.showinfo("Copied", "Hash copied to clipboard.")

ctk.CTkButton(hash_tab, text="Copy Hash", command=copy_hash_to_clipboard).pack(pady=4)

# --- About tab ---
ctk.CTkLabel(about_tab, text="PixelVault256", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=10)
ctk.CTkLabel(about_tab, text="A small steganography + hash utility by david-marin-0xff", wraplength=660).pack(pady=6)
link = ctk.CTkLabel(about_tab, text="GitHub: https://github.com/david-marin-0xff", text_color="lightblue", cursor="hand2")
link.pack()
def open_github(evt=None):
    webbrowser.open("https://github.com/david-marin-0xff")
link.bind("<Button-1>", open_github)

ctk.CTkLabel(about_tab, text="Credits: Uses Pillow, customtkinter, cryptography", text_color="gray").pack(pady=10)
ctk.CTkLabel(app, text="© 2025 PixelVault256", text_color="gray").pack(side="bottom", pady=8)

# Start app
if __name__ == "__main__":
    app.mainloop()
