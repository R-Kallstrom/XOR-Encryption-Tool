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
python xorencrypt.py -f shell.bin -o shell_out.bin -k 0x41

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
python xorencrypt.py -f shell.bin -o shell_out.bin -k 0x4142de --format c

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
[+] Byte Size: 317
[+] Shellcode:
unsigned char buf[] = {
  0xbd, 0x09, 0xc0, 0xa5, 0xb1, 0xbe, 0xbe, 0xbe, 0xa9, 0x8d, 0x41, 0x41, 0x41, 0x00, 0x10, 0x00,
  0x11, 0x13, 0x09, 0x70, 0x93, 0x10, 0x17, 0x24, 0x09, 0xca, 0x13, 0x21, 0x09, 0xca, 0x13, 0x59,
  ...
};
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
[+] Written to output file: shell_out.txt
[+] Byte Size: 317
[+] Shellcode:
payload =
  \xbd\x09\xc0\xa5\xb1\xbe\xbe\xbe\xa9\x8d\x41\x41\x41\x00\x10\x00
  \x11\x13\x09\x70\x93\x10\x17\x24\x09\xca\x13\x21\x09\xca\x13\x59
  ...
```

## Notes

XOR encryption is not **cryptographically secure** and is intended for obfuscation only.

Empty input files and invalid arguments will terminate execution with an error.

Git versioning will fall back to unknown if Git metadata is unavailable.

## Disclaimer

This tool is intended for **educational and authorized security testing purposes only**.
The author is not responsible for misuse.
