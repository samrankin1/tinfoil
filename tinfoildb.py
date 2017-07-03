import os
import sqlite3
import binascii

import cryptoutils

DATABASE_VERSION = 1

DEFAULT_SCRYPT_N = 2 ** 18
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1

DEFAULT_AES_KEY_SIZE = 256 // 8 # 256 bits = 32 bytes

DEFAULT_HMAC_KEY_SIZE = 512 // 8 # 512 bits = 64 bytes

OPCODE = "jX40TyIOkUMMGYLePilPb8BwxSwkYiJ".encode("utf-8")

SCRYPT_SALT_SIZE = 16

class TinfoilDB:
	def __init__(self, database_location):
		self.database = sqlite3.connect(database_location)
		self.master_aes_key = None
		self.master_hmac_key = None

	def check_database_initialized(self):
		cursor = self.database.cursor()

		cursor.execute("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND (name = ? OR name = ?)", ("tinfoil_parameters", "tinfoil_entries"))
		result = cursor.fetchone()[0]

		cursor.close()
		return (result == 2)

	def initialize_database(self, password, scrypt_n = DEFAULT_SCRYPT_N, scrypt_r = DEFAULT_SCRYPT_R, scrypt_p = DEFAULT_SCRYPT_P, aes_key_size = DEFAULT_AES_KEY_SIZE, hmac_key_size = DEFAULT_HMAC_KEY_SIZE):
		if self.check_database_initialized():
			raise AssertionError("database is already initialized!")

		scrypt_salt = cryptoutils.get_random_bytes(length = SCRYPT_SALT_SIZE)
		master_key = cryptoutils.do_scrypt(password = password, salt = scrypt_salt, n = scrypt_n, r = scrypt_r, p = scrypt_p, key_length = (aes_key_size + hmac_key_size))
		master_aes_key = master_key[:aes_key_size]
		master_hmac_key = master_key[aes_key_size:]

		opcode_iv, opcode_encrypted = cryptoutils.aes_encrypt_bytes(data = OPCODE, key = master_aes_key)
		opcode_hmac = cryptoutils.do_hmac(hmac_key = master_hmac_key, aes_encrypted_data = (opcode_iv + opcode_encrypted))

		cursor = self.database.cursor()

		tables = [
		"CREATE TABLE IF NOT EXISTS tinfoil_parameters(version INTEGER NOT NULL, scrypt_n INTEGER NOT NULL, scrypt_r INTEGER NOT NULL, scrypt_p INTEGER NOT NULL, scrypt_salt TEXT NOT NULL, aes_key_size INTEGER NOT NULL, hmac_key_size INTEGER NOT NULL, opcode_plaintext TEXT NOT NULL, opcode_iv TEXT NOT NULL, opcode_encrypted TEXT NOT NULL, opcode_hmac TEXT NOT NULL)",
		"CREATE TABLE IF NOT EXISTS tinfoil_entries(hashed_key TEXT UNIQUE NOT NULL, encrypted_value TEXT NOT NULL, iv TEXT NOT NULL, hmac_signature TEXT NOT NULL)"
		]

		for table in tables:
				cursor.execute(table)

		cursor.execute("INSERT INTO tinfoil_parameters VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (DATABASE_VERSION, scrypt_n, scrypt_r, scrypt_p, scrypt_salt, aes_key_size, hmac_key_size, OPCODE, opcode_iv, opcode_encrypted, opcode_hmac))

		cursor.close()
		self.database.commit()

	def _load_database_parameters(self):
		cursor = self.database.cursor()

		cursor.execute("SELECT version, scrypt_n, scrypt_r, scrypt_p, scrypt_salt, aes_key_size, hmac_key_size, opcode_plaintext, opcode_iv, opcode_encrypted, opcode_hmac FROM tinfoil_parameters")

		results = cursor.fetchall()
		if len(results) != 1:
			raise AssertionError("there must only be 1 row in the tinfoil_parameters table! (found: " + str(len(results)) + ")")

		cursor.close()
		return results[0]

	def check_master_keys_set(self):
		return (self.master_aes_key != None) and (self.master_hmac_key != None)

	def set_master_keys(self, password):
		if self.check_master_keys_set():
			raise AssertionError("master keys are already set!")

		version, scrypt_n, scrypt_r, scrypt_p, scrypt_salt, aes_key_size, hmac_key_size, opcode_plaintext, opcode_iv, opcode_encrypted, opcode_hmac = self._load_database_parameters()

		if version != DATABASE_VERSION:
			raise AssertionError("database version mismatch! expected '" + str(DATABASE_VERSION) + "', got '" + str(version) + "'")

		master_key = cryptoutils.do_scrypt(password = password, salt = scrypt_salt, n = scrypt_n, r = scrypt_r, p = scrypt_p, key_length = (aes_key_size + hmac_key_size))
		master_aes_key = master_key[:aes_key_size]
		master_hmac_key = master_key[aes_key_size:]

		hmac_valid = cryptoutils.verify_hmac(hmac_key = master_hmac_key, aes_encrypted_data = (opcode_iv + opcode_encrypted), signature = opcode_hmac)
		if not hmac_valid:
			return False

		decrypted_opcode = cryptoutils.aes_decrypt_bytes(data = opcode_encrypted, iv = opcode_iv, key = master_aes_key) # todo: catch exception
		success = (decrypted_opcode == opcode_plaintext)

		if success:
			self.master_aes_key = master_aes_key
			self.master_hmac_key = master_hmac_key
			return True
		else:
			return False

	def store_record(self, key, value):
		if not self.check_database_initialized():
			raise AssertionError("database not yet initialized!")
		if not self.check_master_keys_set():
			raise AssertionError("master keys not yet set!")

		cursor = self.database.cursor()

		hashed_key = cryptoutils.do_sha512_hash(data = key)
		iv, encrypted_value = cryptoutils.aes_encrypt_bytes(data = value.encode("utf-8"), key = self.master_aes_key)
		hmac_signature = cryptoutils.do_hmac(hmac_key = self.master_hmac_key, aes_encrypted_data = (iv + encrypted_value))

		try:
			cursor.execute("INSERT INTO tinfoil_entries VALUES(?, ?, ?, ?)", (hashed_key, encrypted_value, iv, hmac_signature))
		except sqlite3.IntegrityError:
			return False
		finally:
			cursor.close()

		self.database.commit()
		return True

	def retrieve_record(self, key):
		if not self.check_database_initialized():
			raise AssertionError("database not yet initialized!")
		if not self.check_master_keys_set():
			raise AssertionError("master keys not yet set!")

		cursor = self.database.cursor()

		hashed_key = cryptoutils.do_sha512_hash(data = key)
		cursor.execute("SELECT encrypted_value, iv, hmac_signature FROM tinfoil_entries WHERE hashed_key = ?", (hashed_key, ))
		result = cursor.fetchone()

		if result == None:
			return None

		encrypted_value, iv, hmac_signature = result # unpack the values

		hmac_valid = cryptoutils.verify_hmac(hmac_key = self.master_hmac_key, aes_encrypted_data = (iv + encrypted_value), signature = hmac_signature)
		if not hmac_valid:
			raise AssertionError("HMAC authentication failed for record with key '" + key + "'!")

		decrypted_value = cryptoutils.aes_decrypt_bytes(data = encrypted_value, iv = iv, key = self.master_aes_key)
		decoded_value = decrypted_value.decode("utf-8")

		cursor.close()
		return decoded_value

	def delete_record(self, key):
		if not self.check_database_initialized():
			raise AssertionError("database not yet initialized!")

		cursor = self.database.cursor()

		hashed_key = cryptoutils.do_sha512_hash(key)
		cursor.execute("DELETE FROM tinfoil_entries WHERE hashed_key = ?", (hashed_key, ))

		cursor.close()
		self.database.commit()

	def close(self):
		self.database.close()
