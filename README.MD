# XOR-Encryption-Tool
A simple command‑line XOR encryption tool for obfuscating shellcode or binary payloads.

The tool supports raw binary output as well as formatted C and Python byte arrays for easy integration into loaders or exploits.

## Features

- XOR encryption with repeating key

- Supports binary input (.bin, .txt, raw shellcode)

- Multiple output formats:

  - Raw bytes

  - C array

  - Python byte array

- Error handling for CLI usage

## Requirements

- Python 3.8+

- Git (optional, for automatic version detection)

## Usage
*Linux*
```
python xorencrypt.py -f <input_file> -o <output_file> -k <key> [--format raw|c|py]
```
*Windows*
```
py xorencrypt.py -f <input_file> -o <output_file> -k <key> [--format raw|c|py]
```
## Arguments
| Argument       | Description                                         |
| -------------- | --------------------------------------------------- |
| `-f, --file`   | Path to input file containing shellcode             |
| `-o, --output` | Path to output file                                 |
| `-k, --key`    | XOR key (string or hex format)                      |
| `--format`     | Output format: `raw`, `c`, or `py` (default: `raw`) |
| `--version`    | Show tool version and exit                          |
| `-h, --help`   | Show help message and exit                          |

## Examples
### Generate a binary payload (raw output)
```
python xorencrypt.py -f shell.bin -o shell_out.bin -k secret

    ┌───────────────────────────────────────────────┐
    │              XOR ENCRYPTION TOOL              │
    │        Payload Obfuscation / Evasion          │
    ├───────────────────────────────────────────────┤
    │ Version : 9b153d7-dirty                       │
    │ Author  : R-Kallstrom                         │
    │ Use     : Shellcode XOR Encoding              │
    └───────────────────────────────────────────────┘

[+] File loaded
[+] XOR encoding complete
[+] Written to output file: shell_out.bin
```
### Generate a C array payload
```
python xorencrypt.py -f shell.txt -o shell_out.txt -k secret --format c

    ┌───────────────────────────────────────────────┐
    │              XOR ENCRYPTION TOOL              │
    │        Payload Obfuscation / Evasion          │
    ├───────────────────────────────────────────────┤
    │ Version : 9b153d7-dirty                       │
    │ Author  : R-Kallstrom                         │
    │ Use     : Shellcode XOR Encoding              │
    └───────────────────────────────────────────────┘

[+] File loaded
[+] XOR encoding complete
[+] Shellcode:
unsigned char buf[] = { 0x2f, 0x1d, 0x50, 0x43, 0x39, 0x0c, 0x10, 0x55, 0x3f, 0x0a, 0x50, 0x44 };
```
### Generate a Python byte array
```
python xorencrypt.py -f shell.txt -o shell_out.txt -k secret --format py

    ┌───────────────────────────────────────────────┐
    │              XOR ENCRYPTION TOOL              │
    │        Payload Obfuscation / Evasion          │
    ├───────────────────────────────────────────────┤
    │ Version : 9b153d7-dirty                       │
    │ Author  : R-Kallstrom                         │
    │ Use     : Shellcode XOR Encoding              │
    └───────────────────────────────────────────────┘

[+] File loaded
[+] XOR encoding complete
[+] Shellcode:
payload = b"\x2f\x1d\x50\x43\x39\x0c\x10\x55\x3f\x0a\x50\x44"
```
    
#### Note

Output files when using '--format raw' (default) will be automaticly written to .bin if other filetype is used in argument.

Output files when using '--format c/py' will be automaticly written to .txt if other filetype is used in argument.

#### raw

**arg:** *-o output_file.txt*  ->  **output:** *output_file.bin*

#### c/py

**arg:** *-o output_file.bin*  ->  **output:** *output_file.txt*

## Notes

XOR encryption is not **cryptographically secure** and is intended for obfuscation only.

Empty input files and invalid arguments will terminate execution with an error.

Git versioning will fall back to unknown if Git metadata is unavailable.

## Disclaimer

This tool is intended for **educational and authorized security testing purposes only**.
The author is not responsible for misuse.
