# PDF TSA Signer

![Static Badge](https://img.shields.io/badge/version-1.0.0-0080c0?style=flat&logo=git&logoColor=ffffff&labelColor=101418)

A command-line utility for digitally signing PDF files with TSA timestamp support.

## Requirements

- Python 3.13+
- `tomlkit`
- `cryptography`
- `pyhanko`

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

1. Put `main.py` in a folder.
2. Run `main.py`.
3. If `config.toml` does not exist, the program will generate a default one at the same directory.
4. You can use your own PFX certificate by filling in the `pfx path` and `pfx password` fields in `config.toml`. If the PFX file is missing, the program will generate a self-signed certificate.
5. Leave `input path` empty to interactively input the PDF file path each time.
6. `output path` is a template. `{input_path_without_extension}` will be replaced with the input file path without extension.