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
    Decrypts a file using GPG encryption. Assumes the decrypted file should be placed in the same directory as the encrypted file.
    :param encrypted_file_path: Path to the encrypted file.
    :param encryption_key: Encryption key for decryption.
    :return: Path to the decrypted file.
    """
    gpg = gnupg.GPG()
    temp_dir = os.path.dirname(encrypted_file_path)  # Derive directory from input path
    _, file_extension = os.path.splitext(encrypted_file_path)
    # Ensure the output filename is distinct from the input
    decrypted_filename = f"decrypted_{os.path.basename(encrypted_file_path).replace('encrypted_', '', 1)}"
    decrypted_file_path = os.path.join(temp_dir, decrypted_filename)

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
