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
### XOR‑encode a binary payload (raw output)
    python xor_tool.py -f shellcode.bin -o encrypted.bin -k secret

### Generate a C array payload
    python xor_tool.py -f shellcode.bin -o payload.txt -k secret --format c

### Generate a Python byte array
    python xor_tool.py -f shellcode.bin -o payload.txt -k secret --format py
    
#### Note
Output files when using '--format c/py' will be automaticly written to .txt if other filetype is used in argument.

**arg:** *-o output_file.bin*  ->  **output:** *output_file.txt*

## Example Output
### Example C Array Output

```c
unsigned char payload[] = { 0x31, 0x9f, 0x42, 0xa1, 0x7d, 0x88 };
```
### Example Python Byte Array Output
```py
payload = b"\x31\x9f\x42\xa1\x7d\x88"
```
## Notes

XOR encryption is not **cryptographically secure** and is intended for obfuscation only.

Empty input files and invalid arguments will terminate execution with an error.

Git versioning will fall back to unknown if Git metadata is unavailable.

## Disclaimer

This tool is intended for **educational and authorized security testing purposes only**.
The author is not responsible for misuse.
