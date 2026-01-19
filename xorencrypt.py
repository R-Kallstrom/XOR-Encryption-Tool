import argparse, re, sys, subprocess

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
        help="Path to file containing shellcode"
    )
    parser.add_argument(
        "-o", "--output", 
        required=True, 
        help="""Path to output file. Depending on --format used,
        the file type may vary: raw = .bin, c/py = .txt and 
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
    input_file = load_file(args.file)
    shell_encoded = xor_encrypt(input_file, args.key)
    write_file(args.output, shell_encoded, args.format)
# Main end()


#   ====== FUNCTIONS ======

    # XOR encryption #
def xor_encrypt(data, inKey):
    """
    XOR-encrypts binary data using a repeating key.

    Args:
        data (bytes | bytearray): Binary data to encrypt.
        inKey (str): Encryption key (UTF-8 encoded).

    Returns:
        bytes: XOR-encrypted output.
    """
    key = inKey.encode()
    out = bytearray()

    for i, byte in enumerate(data):
        out.append(byte ^ key[i % len(key)])

    print("[+] XOR encoding complete")
    return bytes(out)


#   ====== FILE HANDLING ======

    ## Input ##
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
def write_file(path, shell_encrypted, format):
    """
    Writes encrypted shellcode to file and terminal in the specified format.

    Args:
        path (str): Output file path.
        shell_encrypted (bytes): Encrypted shellcode data.
        format (str): Output format ("raw", "c", or "py").

    Output:
        Write to .bin or .txt depending on format. Will print output to terminal if format is "c" or "py".
    """
    # Output in raw bytes
    if format == "raw":
        path = re.sub("[.].+", ".bin", path)
        with open(path, "wb") as file:
            file.write(shell_encrypted)
        print(f"[+] Written to output file: {path}")

    # Output as C-array
    if format == "c":
        path = re.sub("[.].+", ".txt", path)
        with open(path, "w") as file:
            encrypted_c = shell_encrypted.hex()
            hex_bytes = [encrypted_c[i:i + 2] for i in range(0, len(encrypted_c), 2)]
            lines = [", 0x".join(hex_bytes[i:i + 16]) for i in range(0, len(hex_bytes), 16)]
            encrypted_c = ("unsigned char buf[] = {\n  0x" + ",\n  0x".join(lines) + "\n};")
            file.write(encrypted_c)
        print("[+] Shellcode:\n", encrypted_c)

    # Output as Python-array
    if format == "py":
        path = re.sub("[.].+", ".txt", path)
        with open(path, "w") as file:
            encrypted_py = shell_encrypted.hex()
            hex_bytes = [encrypted_py[i:i + 2] for i in range(0, len(encrypted_py), 2)]
            lines = ["\\x".join(hex_bytes[i:i + 16]) for i in range(0, len(hex_bytes), 16)]
            encrypted_py = ("payload = \n  \\x" + "\n  \\x".join(lines) + "\n")
            file.write(encrypted_py)
        print("[+] Shellcode:\n", encrypted_py)


# ====== STYLING ======
def get_git_version():
    try:
        return subprocess.check_output(
            ["git", "describe", "--tags", "--dirty", "--always"],
            stderr=subprocess.DEVNULL,
            text=True
        ).strip()
    except Exception:
        return "unknown"
    
    # Banner #
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
