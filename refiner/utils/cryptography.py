import os
from typing import Union

import gnupg
import vana
from Crypto.Cipher import AES
from Crypto.Hash import SHA512, HMAC, SHA256
from coincurve import PrivateKey, PublicKey
from ecies.utils import hex2pk

from refiner.errors.exceptions import FileDecryptionError


def decrypt_file(encrypted_file_path: str, encryption_key: str) -> str:
    """
    Decrypts a file using GPG encryption. The decrypted file is placed
    in an 'input' subdirectory within the same directory as the encrypted file.

    Args:
        encrypted_file_path (str): Path to the encrypted file.
        encryption_key (str): Encryption key for decryption.

    Returns:
        str: Path to the decrypted file (inside the 'input' subdirectory).

    Raises:
        FileDecryptionError: If decryption fails or the input directory cannot be created.
    """
    gpg = gnupg.GPG()
    base_temp_dir = os.path.dirname(encrypted_file_path)  # Directory containing the encrypted file
    input_dir = os.path.join(base_temp_dir, 'input')      # Target 'input' subdirectory

    # Create the 'input' subdirectory if it doesn't exist
    try:
        os.makedirs(input_dir, exist_ok=True)
        vana.logging.info(f"Ensured input directory exists: {input_dir}")
    except OSError as e:
         raise FileDecryptionError(error=f"Could not create input directory '{input_dir}': {e}")

    _, file_extension = os.path.splitext(encrypted_file_path)
    # Keep a simple name for the decrypted file inside the input dir
    decrypted_filename = f"decrypted_file{file_extension}"
    decrypted_file_path = os.path.join(input_dir, decrypted_filename) # Path inside input/

    try:
        with open(encrypted_file_path, 'rb') as encrypted_file:
            decrypted_data = gpg.decrypt_file(
                encrypted_file,
                passphrase=encryption_key,
                output=decrypted_file_path
            )

            vana.logging.info(f"GPG decryption status: {decrypted_data.status}")
            vana.logging.debug(f"GPG stderr: {decrypted_data.stderr}")

            if not decrypted_data.ok:
                try:
                    if os.path.exists(decrypted_file_path):
                        os.remove(decrypted_file_path)
                except OSError:
                    pass
                raise FileDecryptionError(
                    error=f"GPG decryption failed: Status '{decrypted_data.status}', Stderr: '{decrypted_data.stderr}'"
                )

    except Exception as e:
        try:
            if os.path.exists(decrypted_file_path):
                os.remove(decrypted_file_path)
        except OSError:
            pass
        if isinstance(e, FileDecryptionError):
            raise
        else:
            raise FileDecryptionError(error=f"An unexpected error occurred during decryption: {str(e)}")

    vana.logging.info(f"Successfully decrypted file to: {decrypted_file_path}")
    return decrypted_file_path


def ecies_encrypt(receiver_pk: Union[str, bytes], msg: bytes) -> tuple[bytes, PrivateKey, bytes]:
    """
    Encrypt with receiver's secp256k1 public key
    :param receiver_pk: Receiver's public key (hex str or bytes)
    :param msg: Data to encrypt
    :return: Encrypted data
    """
    if isinstance(receiver_pk, str):
        pk = hex2pk(receiver_pk)
    elif isinstance(receiver_pk, bytes):
        pk = PublicKey(receiver_pk)
    else:
        raise TypeError("Invalid public key type")

    # Generate ephemeral key pair
    ephemeral_sk = PrivateKey()
    ephemeral_pk = ephemeral_sk.public_key.format(compressed=False)

    # Derive shared secret
    shared_point = pk.multiply(ephemeral_sk.secret)
    px = shared_point.format(compressed=True)[1:]

    # Generate encryption and MAC keys using SHA512
    hash_px = SHA512.new(px).digest()
    encryption_key = hash_px[:32]
    mac_key = hash_px[32:]

    # Generate IV and encrypt
    iv = os.urandom(16)
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    padding_length = 16 - (len(msg) % 16)
    padded_msg = msg + bytes([padding_length] * padding_length)
    encrypted = cipher.encrypt(padded_msg)

    # Generate MAC
    data_to_mac = b"".join([iv, ephemeral_pk, encrypted])
    mac = HMAC.new(mac_key, data_to_mac, SHA256).digest()[:32]

    # Combine all components
    rsp = iv + ephemeral_pk + encrypted + mac
    return rsp, ephemeral_sk, iv
