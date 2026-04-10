from typing import Callable, NoReturn
from dataclasses import dataclass

import os
import sys
from datetime import datetime, timedelta, timezone

import tomlkit
import tomlkit.items
import tomlkit.exceptions

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pyhanko.sign.timestamps import HTTPTimeStamper


CONFIG_PATH = 'config.toml'

doc = tomlkit.document()
doc_json = {
    'certificate': {
        'cert path': 'selfsigned.pfx',
        'cert password': ''
    },
    'tsa': {
        'tsa server url': 'http://timestamp.digicert.com'
    },
    'pdf': {
        'input path': tomlkit.item('').comment('Empty string means ask user to input the path interactively'),
        'output path': "{input_path_without_extension}_signed.pdf"
    }
}
doc.update(doc_json)
CONFIG_KEYS = {k: v.keys() for k, v in doc_json.items()}
DEFAULT_CONFIG = doc
del doc_json
del doc

ROOT = os.path.dirname(os.path.abspath(__file__))


def exit_with_error(message: str) -> NoReturn:
    print(message)
    os.system("pause")
    sys.exit(1)


def input_with_validation(prompt: str, validation_func: Callable[[str], bool] = lambda x: True, invalid_message: str = "") -> str:
    try:
        value = input(prompt)
        while not validation_func(value):
            print(f"[ERROR] {invalid_message}")
            value = input(prompt)
        return value
    except EOFError:
        print("[ERROR] Invalid input.")
        return input_with_validation(prompt, validation_func, invalid_message)


def input_choice(prompt: str, valid_choices: tuple[str, ...]) -> str:
    return input_with_validation(
        prompt,
        lambda x: x.lower() in valid_choices,
        f"Please enter one of the following choices: {', '.join(valid_choices)}"
    )


def input_non_empty(prompt: str) -> str:
    return input_with_validation(
        prompt,
        lambda x: x.strip() != '',
        "Empty input is not allowed."
    )


def input_str(prompt: str) -> str:
    return input_with_validation(
        prompt
    )


def input_positive_integer(prompt: str) -> str:
    return input_with_validation(
        prompt,
        lambda x: x.isdigit() and int(x) > 0,
        "Please enter a positive integer."
    )


def input_raw(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        print("[ERROR] Invalid input.")
        return input_raw(prompt)


def input_certificate_password(prompt: str) -> str:
    try:
        value = input(prompt)
        while value == "" or "\x00" in value:
            print("[ERROR] Password cannot be empty and cannot contain embedded NUL characters.")
            value = input(prompt)
        return value
    except EOFError:
        print("[ERROR] Invalid input.")
        return input_certificate_password(prompt)


@dataclass
class Config:
    cert_path: str
    cert_password: str
    tsa_server_url: str
    input_path: str
    output_path: str

    @classmethod
    def from_toml(cls, config: tomlkit.TOMLDocument) -> "Config":
        section_certificate = cls._get_table(config, "certificate")
        section_tsa = cls._get_table(config, "tsa")
        section_pdf = cls._get_table(config, "pdf")

        cert_path = cls._get_string(section_certificate, "cert path")
        cert_password = cls._get_string(section_certificate, "cert password")
        tsa_server_url = cls._get_string(section_tsa, "tsa server url")
        input_path = cls._get_string(section_pdf, "input path")
        output_path = cls._get_string(section_pdf, "output path")

        config_obj = cls(
            cert_path=cert_path,
            cert_password=cert_password,
            tsa_server_url=tsa_server_url,
            input_path=input_path,
            output_path=output_path,
        )
        return config_obj

    def to_toml(self) -> tomlkit.TOMLDocument:
        doc = tomlkit.document()
        doc.update({
            'certificate': {
                'cert path': self.cert_path,
                'cert password': self.cert_password,
            },
            'tsa': {
                'tsa server url': self.tsa_server_url,
            },
            'pdf': {
                'input path': self.input_path,
                'output path': self.output_path,
            }
        })
        return doc

    @staticmethod
    def _get_table(config: tomlkit.TOMLDocument, section: str) -> tomlkit.items.Table:
        table = config.get(section)
        if table is None or not isinstance(table, tomlkit.items.Table):
            exit_with_error(f"[CRITICAL] Missing section: [{section}] in config. If you cannot fix the config file manually, please delete the file and run the program again to generate a new default config file.")
        return table

    @staticmethod
    def _get_string(table: tomlkit.items.Table, key: str) -> str:
        value = table.get(key)
        if value is None:
            exit_with_error(f"[CRITICAL] Missing key '{key}' in config. If you cannot fix the config file manually, please delete the file and run the program again to generate a new default config file.")
        if not isinstance(value, str):
            exit_with_error(f"[CRITICAL] Invalid config: value for '{key}' must be a string.")
        return value


def generate_self_signed_certificate(cert_path: str) -> str:
    '''
    Generate a self-signed certificate and save it as a PFX file. Attribute values and password will be provided by user input interactively.

    :param cert_path: The path where the generated certificate file will be saved.

    :return: The password used for the certificate file.
    '''

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Collect inputs; do not impose extra certificate subject restrictions beyond the password.
    country_name = input_raw("Country Name (2 letter code) [AU]: ")
    state_or_province_name = input_raw("State or Province Name (full name) [Some-State]: ")
    locality_name = input_raw("Locality Name (eg, city) []: ")
    organization_name = input_raw("Organization Name (eg, company) [Internet Widgits Pty Ltd]: ")
    organizational_unit_name = input_raw("Organizational Unit Name (eg, section) []: ")
    common_name = input_raw("Common Name (e.g. server FQDN or YOUR name) []: ")

    distinguished_names = []
    if country_name:
        distinguished_names.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country_name))
    if state_or_province_name:
        distinguished_names.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name))
    if locality_name:
        distinguished_names.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name))
    if organization_name:
        distinguished_names.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name))
    if organizational_unit_name:
        distinguished_names.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit_name))
    if common_name:
        distinguished_names.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))

    subject = issuer = x509.Name(distinguished_names)

    validity_period = int(input_positive_integer("Validity Period (in days) [365]: "))

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_period))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, algorithm=hashes.SHA256())
    )

    friendly_name = input_raw("Friendly Name for the certificate: ")
    cert_password = input_certificate_password("Password for the certificate file: ")

    cert_data = pkcs12.serialize_key_and_certificates(
        name=friendly_name.encode('utf-8'),
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(cert_password.encode('utf-8'))
    )

    try:
        with open(cert_path, 'wb') as f:
            f.write(cert_data)
    except FileNotFoundError:
        exit_with_error(f"[CRITICAL] Invalid path for the certificate file: '{cert_path}'.")
    except IsADirectoryError:
        exit_with_error(f"[CRITICAL] Certificate path '{cert_path}' is a directory.")
    except PermissionError:
        exit_with_error(f"[CRITICAL] Do not have permission to write the certificate file at '{cert_path}', or it's being used by another program.")
    except OSError as e:
        exit_with_error(f"[CRITICAL] An unknown error occurred while writing the certificate file:\n    {e}")
    except Exception as e:
        exit_with_error(f"[CRITICAL] Unexpected error while writing the certificate file: {e}")

    print(f"[INFO] Successfully generated and saved self-signed certificate at '{cert_path}'.")

    return cert_password


def sign_pdf_with_self_signed_and_digicert_tsa(input_path: str, output_path: str, cert_path: str, cert_password: str, tsa_server_url: str) -> None:
    try:
        signer = signers.SimpleSigner.load_pkcs12(
            pfx_file=cert_path,
            passphrase=cert_password.encode('utf-8')
        )
    except (ValueError, OSError) as e:
        exit_with_error(f"[CRITICAL] Failed to load the PFX file: {e}")

    if signer is None:
        exit_with_error("[CRITICAL] Failed to load the PFX file. Invalid path or incorrect password.")

    ts_client = HTTPTimeStamper(tsa_server_url)

    try:
        with open(input_path, 'rb') as in_pdf:
            w = IncrementalPdfFileWriter(in_pdf)
            if os.path.isfile(output_path):
                print(f"[WARNING] Output file '{output_path}' already exists.")
                choice = input_choice("Do you want to overwrite it(O) or exit(E): ", ('o', 'e'))
                if choice == 'e':
                    os.system("pause")
                    sys.exit(0)
            try:
                with open(output_path, 'wb') as out_pdf:
                    signers.sign_pdf(
                        w,
                        signers.PdfSignatureMetadata(field_name='Signature_with_TSA'),
                        signer=signer,
                        timestamper=ts_client,
                        output=out_pdf
                    )
            except FileNotFoundError:
                exit_with_error(f"[CRITICAL] Invalid output path: '{output_path}'.")
            except IsADirectoryError:
                exit_with_error(f"[CRITICAL] Output path '{output_path}' is a directory.")
            except PermissionError:
                exit_with_error(f"[CRITICAL] Do not have permission to write the output file at '{output_path}', or it's being used by another program.")
            except OSError as e:
                exit_with_error(f"[CRITICAL] An unknown error occurred while writing the signed PDF:\n    {e}")
            except Exception as e:
                exit_with_error(f"[CRITICAL] Unexpected error while signing PDF: {e}")
    except FileNotFoundError:
        exit_with_error(f"[CRITICAL] Input file not found at '{input_path}'.")
    except IsADirectoryError:
        exit_with_error(f"[CRITICAL] Input path '{input_path}' is a directory.")
    except PermissionError:
        exit_with_error(f"[CRITICAL] Do not have permission to read the input file at '{input_path}', or it's being used by another program.")
    except OSError as e:
        exit_with_error(f"[CRITICAL] An unknown error occurred while reading the input file:\n    {e}")
    except Exception as e:
        exit_with_error(f"[CRITICAL] Unexpected error while signing PDF: {e}")

    print(f"[INFO] Successfully signed the PDF file with TSA from {tsa_server_url}. Saved as: {output_path}")


def load_toml(config_path) -> tomlkit.TOMLDocument:
    try:
        with open(os.path.join(ROOT, config_path), 'r', encoding='utf-8') as f:
            config = tomlkit.load(f)
    except FileNotFoundError:
        config = write_default_config(config_path)
        print(f"[INFO] No config file found. A new default config file has been created at '{config_path}'.")
        choice = input_choice("Exit to edit the config file(E) or continue(C): ", ('e', 'c'))
        if choice == 'e':
            os.system("pause")
            sys.exit(0)
    except IsADirectoryError:
        exit_with_error(f"[CRITICAL] '{config_path}' should be remained for config file, please delete the directory with the same name.")
    except UnicodeDecodeError:
        exit_with_error(f"[CRITICAL] Failed to read '{config_path}' in utf-8 encoding. If you cannot fix it manually, please delete the file and run the program again to generate a new default config file.")
    except PermissionError:
        exit_with_error(f"[CRITICAL] Do not have permission to read '{config_path}', or it's being used by another program.")
    except OSError as e:
        exit_with_error(f"[CRITICAL] An unknown error occurred while reading '{config_path}':\n    {e}")
    except tomlkit.exceptions.TOMLKitError as e:
        exit_with_error(f"[CRITICAL] A TOML error occurred while parsing the config file:\n    {e}")
    except Exception as e:
        exit_with_error(f"[CRITICAL] Unexpected error while reading '{config_path}':\n    {e}")
    return config


def write_default_config(config_path) -> tomlkit.TOMLDocument:
    if os.path.isfile(os.path.join(ROOT, config_path)):
        exit_with_error(f"[UNEXPECTED] The config file '{config_path}' already exists, while trying to create a new default config file.")
    try:
        with open(os.path.join(ROOT, config_path), 'w', encoding='utf-8') as f:
            tomlkit.dump(DEFAULT_CONFIG, f)
    except IsADirectoryError:
        exit_with_error(f"[CRITICAL] '{config_path}' should be remained for config file, please delete the directory with the same name.")
    except UnicodeEncodeError:
        exit_with_error(f"[CRITICAL] Failed to write '{config_path}' in utf-8 encoding. If you cannot fix it manually, please delete the file and run the program again to generate a new default config file.")
    except PermissionError:
        exit_with_error(f"[CRITICAL] Do not have permission to write '{config_path}', or it's being used by another program.")
    except OSError as e:
        exit_with_error(f"[CRITICAL] An unknown error occurred while writing '{config_path}':\n    {e}")
    except tomlkit.exceptions.TOMLKitError as e:
        exit_with_error(f"[UNEXPECTED] A TOML error occurred while writing the default config file:\n    {e}")
    except Exception as e:
        exit_with_error(f"[CRITICAL] Unexpected error while writing '{config_path}':\n    {e}")
    return DEFAULT_CONFIG


def write_config(config_path: str, config: "Config") -> None:
    try:
        with open(os.path.join(ROOT, config_path), 'w', encoding='utf-8') as f:
            tomlkit.dump(config.to_toml(), f)
    except FileNotFoundError:
        exit_with_error(f"[UNEXPECTED] Invalid path for the config file: '{config_path}'.")
    except IsADirectoryError:
        exit_with_error(f"[CRITICAL] '{config_path}' should be remained for config file, please delete the directory with the same name.")
    except PermissionError:
        exit_with_error(f"[CRITICAL] Do not have permission to write '{config_path}', or it's being used by another program.")
    except UnicodeEncodeError:
        exit_with_error(f"[UNEXPECTED] Failed to write '{config_path}' in utf-8 encoding.")
    except OSError as e:
        exit_with_error(f"[CRITICAL] An unknown error occurred while writing '{config_path}':\n    {e}")
    except tomlkit.exceptions.TOMLKitError as e:
        exit_with_error(f"[CRITICAL] A TOML error occurred while writing the config file:\n    {e}")
    except Exception as e:
        exit_with_error(f"[CRITICAL] Unexpected error while writing '{config_path}':\n    {e}")


if __name__ == "__main__":
    try:
        config = Config.from_toml(load_toml(CONFIG_PATH))

        if not os.path.exists(config.cert_path):
            print(f"[WARNING] Certificate file not found at '{config.cert_path}'.")
            choice = input_choice("Do you want to generate a self-signed certificate(G) or exit(E): ", ('g', 'e'))
            if choice == 'e':
                os.system("pause")
                sys.exit(0)

            config.cert_password = generate_self_signed_certificate(config.cert_path)
            write_config(CONFIG_PATH, config)

        input_path = config.input_path if config.input_path else input_non_empty("Please enter the path of the PDF file to be signed: ")
        output_path = config.output_path.replace('{input_path_without_extension}', os.path.splitext(input_path)[0])

        sign_pdf_with_self_signed_and_digicert_tsa(
            input_path=input_path,
            output_path=output_path,
            cert_path=config.cert_path,
            cert_password=config.cert_password,
            tsa_server_url=config.tsa_server_url
        )

        os.system("pause")
    except Exception as e:
        exit_with_error(f"[CRITICAL] Unexpected fatal error: {e}")
