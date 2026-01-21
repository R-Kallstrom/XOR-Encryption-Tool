import argparse, re, sys, subprocess
from pathlib import Path

def main():
    """
    CLI entry point for the XOR encoding tool.

    Parses command-line arguments, loads input shellcode, XOR-encodes it
    using the provided key, and writes the output in the selected format.
    """
    version = get_git_version()

#   ====== ARGUMENTS ======    
    parser = argparse.ArgumentParser(description="XOR Encoding Tool")

    parser.add_argument(
        "-f", "--file",
        required=True,
        help="Path to file containing shellcode. .bin or .txt is accepted"
    )
    parser.add_argument(
        "-o", "--output", 
        required=True, 
        help="""Path to output file. Shellcode when format c/py 
        will print to terminal"""
    )
    parser.add_argument(
        "-k", "--key", 
        required=True, 
        help="XOR-key in String or Hex format"
    )
    parser.add_argument(
        "--format", 
        default="raw", 
        help="Type of format to output (raw : Raw bytes | c : C-array | py : Python-array). Raw is used by default." , 
        choices=["raw", "c", "py"]
    )
    parser.add_argument(
        "--version", 
        action="version", 
        version=f"%(prog)s {version}"
    )

    args = parser.parse_args()

#   ====== RUN ====== 
    print_banner(version)

    ## Check if input is .bin or .txt file ##
    if ".bin" in args.file:
        input_file = load_file(args.file)
        key = parse_key(args.key)
        shell_encoded = xor_encrypt_bin(input_file, key)
        write_file(args.output, shell_encoded, args.format, ".bin")

    elif ".txt" in args.file:
        input_file = parse_shellcode_txt(args.file)
        key = parse_key(args.key)
        shell_encoded = xor_encrypt_txt(input_file, key)
        write_file(args.output, shell_encoded, args.format, ".txt")
    # write_file(args.output, shell_encoded)
# Main end()


#   ====== FUNCTIONS ======

    ## XOR encryption for .bin shellcode ##
def xor_encrypt_bin(data, key_bytes):
    """
    XOR-encrypt binary data using a repeating key.

    Args:
        data (bytes | bytearray): Data to encrypt.
        key_bytes (bytes): Repeating XOR key.

    Returns:
        bytearray: Encrypted output.
    """
    encrypted_shellcode = bytearray()
    key_len = len(key_bytes)

    for i, b in enumerate(data):
        encrypted_shellcode.append(b ^ key_bytes[i % key_len])
    print("[+] XOR encoding complete")
    return encrypted_shellcode

    ## XOR encryption for .txt shellcode##
def xor_encrypt_txt(data: bytes, key: bytes) -> bytes:
    """
    XOR-encrypt text-based shellcode using a repeating key.

    Args:
        data (bytes): Data to encrypt.
        key (bytes): Repeating XOR key.

    Returns:
        bytes: Encrypted output.
    """
    encrypted_shellcode = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    print("[+] XOR encoding complete")
    return encrypted_shellcode

    ## Key Converter ##
def parse_key(key : str) -> bytes:
    """
    Convert a key string to bytes.

    Args:
        key (str): A hex string prefixed with "0x" or a plain text string.

    Returns:
        bytes: The parsed key as bytes.
    """
    if key.startswith("0x"):
        return bytes.fromhex(key[2:])
    return key.encode()


#   ====== FILE HANDLING ======

    ## File reader for .txt file ##
def parse_shellcode_txt(path: str) -> bytes:
    """Parses hex-encoded shellcode from a text file.

    Supports escaped hex (e.g. "\\x90\\x90"), space-separated bytes,
    and ignores commas and newlines.

    Args:
        path (str): Path to the shellcode text file.

    Returns:
        bytes: Parsed shellcode bytes.

    Exits:
        Terminates the program if the file is empty, missing, or unreadable.
    """
    try:
        text = Path(path).read_text().strip()
        text = text.replace("\\x", "").replace(",", "").replace("\n", "").replace("\"","")

    except FileNotFoundError:
        print(f"[-] File not found: {path}")
        sys.exit(1)

    except Exception as e:
        print(f"[-] {e}")
        sys.exit(1)

    else:
        print("[+] File loaded")    
        return bytes.fromhex(text)

    ## File reader for .bin file ##
def load_file(path):
    """
    Loads binary data from a file.

    Args:
        path (str): Path to a .bin or .txt file to read in binary mode.

    Returns:
        bytes: File contents.

    Exits:
        Terminates the program if the file is empty, missing, or unreadable.
    """
    try:
        with open(path, "rb") as file:
            file_code = file.read()

            if not file_code:
                print(f"File is empty: {path}")
                sys.exit(1)

    except FileNotFoundError:
        print(f"[-] File not found: {path}")
        sys.exit(1)

    except Exception as e:
        print(f"[-] {e}")
        sys.exit(1)

    else:
        print("[+] File loaded")
        return file_code

    ## Output ##
def write_file(path, shell_encrypted, format, f_type):
    """
    Writes encrypted shellcode to file in the specified format.

    Args:
        path (str): Output file path.
        shell_encrypted (bytes): Encrypted shellcode data.
        format (str): Output format ("raw", "c", or "py").

    Output:
        Write to output file. Will print output to terminal if format is "c" or "py". Shellcode byte size.
    """
    # Output to .bin file #
    if f_type == ".bin":
        with open(path, "wb") as file:
            file.write(shell_encrypted)
        print(f"[+] Written to output file: {path}")
        print(f"[+] Byte Size: {len(shell_encrypted)}")
        if format == "c":
            print_to_terminal(shell_encrypted, "c")
        elif format == "py":
            print_to_terminal(shell_encrypted, "py")

    # # Output as C-array #
    elif f_type == ".txt" and format == "c":
        with open(path, "w") as file:
            encrypted_c = shell_encrypted.hex()
            print_to_terminal(encrypted_c, "c")
            file.write(encrypted_c)
        print(f"[+] Byte Size: {len(shell_encrypted)}")

    # # Output as Python-array #
    elif f_type == ".txt" and format ==  "py":
        with open(path, "w") as file:
            encrypted_py = shell_encrypted.hex()
            print_to_terminal(encrypted_py, "py")
            file.write(encrypted_py)
        print(f"[+] Byte Size: {len(shell_encrypted)}")

    ## Terminal output ##
def print_to_terminal(shell_encrypted, format):
    """
    Writes encrypted shellcode to terminal in the specified format.

    Args:
        shell_encrypted (bytes): Encrypted shellcode data.
        format (str): Output format ("raw", "c", or "py").

    Output:
        Shellcode in "c" or "py" text format.
    """
    if format == "c":
        encrypted_c = shell_encrypted.hex()
        hex_bytes = [encrypted_c[i:i + 2] for i in range(0, len(encrypted_c), 2)]
        lines = [", 0x".join(hex_bytes[i:i + 16]) for i in range(0, len(hex_bytes), 16)]
        encrypted_c = ("unsigned char buf[] = {\n  0x" + ",\n  0x".join(lines) + "\n};")
        print("[+] Shellcode:")
        print(encrypted_c)
    
    elif format == "py":
        encrypted_py = shell_encrypted.hex()
        hex_bytes = [encrypted_py[i:i + 2] for i in range(0, len(encrypted_py), 2)]
        lines = ["\\x".join(hex_bytes[i:i + 16]) for i in range(0, len(hex_bytes), 16)]
        encrypted_py = ("payload = \n  \\x" + "\n  \\x".join(lines) + "\n")
        print("[+] Shellcode:")
        print (encrypted_py)

# ====== STYLING ======

    ## Version handler ##
def get_git_version():
    try:
        return subprocess.check_output(
            ["git", "describe", "--tags", "--dirty", "--always"],
            stderr=subprocess.DEVNULL,
            text=True
        ).strip()
    except Exception:
        return "unknown"

    ## Banner ##
def print_banner(version):
    banner = rf"""
    ┌───────────────────────────────────────────────┐
    │              XOR ENCRYPTION TOOL              │
    │        Payload Obfuscation / Evasion          │
    ├───────────────────────────────────────────────┤
    │ Version : {version:<33}   │
    │ Author  : R-Kallstrom                         │
    │ Use     : Shellcode XOR Encoding              │
    └───────────────────────────────────────────────┘
    """
    print(banner)

if __name__ == "__main__":
    main()
