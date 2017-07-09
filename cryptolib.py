import os

import scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.primitives import hashes, padding as symmetric_padding, hmac

backend = default_backend()

def do_sha512_hash(data):
	"""Calculate the SHA-512 hash for the given data"""
	if type(data) != bytes:
		data = data.encode("utf-8")

	digest = hashes.Hash(
		algorithm = hashes.SHA512(),
		backend = backend
	)
	digest.update(data)
	return digest.finalize()

def get_random_bytes(length):
	"""Generate cryptographically secure random bytes of the given length"""
	return os.urandom(length)

def do_scrypt(password, salt, n, r, p, key_length):
	"""Derive a cryptographic key using the Scrypt algorithm with the given parameters"""
	if type(password) != bytes:
		password = password.encode("utf-8")

	return scrypt.hash(password = password, salt = salt, N = n, r = r, p = p, buflen = key_length)

def _pad_bytes(data):
	"""Pad bytes of data for encryption by a CBC-mode AES cipher"""
	padder = symmetric_padding.PKCS7(algorithms.AES.block_size).padder()
	padded_data = padder.update(data)
	padded_data += padder.finalize()
	return padded_data

def _unpad_bytes(data):
	"""Unpad bytes of data that were padded by _pad_bytes"""
	unpadder = symmetric_padding.PKCS7(algorithms.AES.block_size).unpadder()
	unpadded_data = unpadder.update(data)
	unpadded_data += unpadder.finalize()
	return unpadded_data

def aes_encrypt_bytes(data, key):
	"""Encrypt some data with the given AES key"""
	padded_data = _pad_bytes(data)
	iv = get_random_bytes((algorithms.AES.block_size // 8))
	encryptor = Cipher(
		algorithm = algorithms.AES(key),
		mode = modes.CBC(iv),
		backend = backend
	).encryptor()
	return iv, (encryptor.update(padded_data) + encryptor.finalize())

def aes_decrypt_bytes(data, iv, key):
	"""Decrypt data that was encrypted by _aes_encrypt_bytes"""
	decryptor = Cipher(
		algorithm = algorithms.AES(key),
		mode = modes.CBC(iv),
		backend = backend
	).decryptor()
	decrypted_data = decryptor.update(data) + decryptor.finalize()
	return _unpad_bytes(decrypted_data)

def do_hmac(hmac_key, aes_encrypted_data):
	"""Generate a HMAC signature for the given encrypted data and HMAC key"""
	signer = hmac.HMAC(
		key = hmac_key,
		algorithm = hashes.SHA512(),
		backend = backend
	)
	signer.update(aes_encrypted_data)
	return signer.finalize()

def verify_hmac(hmac_key, aes_encrypted_data, signature):
	"""Verify a HMAC signature for the given encrypted data and HMAC key"""
	verifier = hmac.HMAC(
		key = hmac_key,
		algorithm = hashes.SHA512(),
		backend = backend
	)
	verifier.update(aes_encrypted_data)
	try:
		verifier.verify(signature)
		return True
	except: # if verifying the signature fails for any reason, return failure
		return False
