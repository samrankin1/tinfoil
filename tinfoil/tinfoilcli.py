#!/bin/python3

import sys
import cmd
import getpass

import pyperclip as clipboard

from . import inputlib, passwordlib
from .tinfoillib import TinfoilDB

DEFAULT_DATABASE = "tinfoil.db"
DEFAULT_SCRYPT_N = 19
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1

SCRYPT_N_MINIMUM = 14
SCRYPT_N_MAXIMUM = 23

AES_KEY_SIZE = 256 // 8 # 256 bits = 32 bytes

HMAC_KEY_SIZE = 512 // 8 # 512 bits = 64 bytes

DEFAULT_PASSWORD_LENGTH = 40
DEFAULT_PASSWORD_DIGITS = True
DEFAULT_PASSWORD_SPECIAL_CHARACTERS = True
DEFAULT_PASSWORD_SPACES = True

database = None

def bool_to_y_n(value):
	if value == True:
		return "[Y/n]"
	elif value == False:
		return "[y/N]"
	else:
		return None

def is_valid_N(number):
	# between the static minimum and maximum, inclusive
	return (number >= SCRYPT_N_MINIMUM) and (number <= SCRYPT_N_MAXIMUM)

def is_valid_r(number):
	return (number > 0)

def is_valid_p(number):
	return (number > 0)

def is_valid_length(number):
	return (number > 0)

def is_valid_password(string):
	return True

def ask_database_password():
	user_input = getpass.getpass("database master password: ")
	if not user_input:
		return None
	else:
		return user_input

def ask_database_parameters():
	print()
	print("--- database first-time setup ---")
	print()

	print("[master key work factor]")
	print("larger values are more secure but slower")
	print("please refer to 'tinfoil-spd' to determine an optimal value for your hardware")
	print("it must be an integer between " + str(SCRYPT_N_MINIMUM) + " and " + str(SCRYPT_N_MAXIMUM) + " (inclusive); the default is " + str(DEFAULT_SCRYPT_N))
	scrypt_n_input_args = ("scrypt work factor [def: " + str(DEFAULT_SCRYPT_N) + "]: ", )
	scrypt_n_input_kwargs = {"default": DEFAULT_SCRYPT_N, "verification_function": is_valid_N}
	scrypt_n_error_message = "work factor must be an integer between " + str(SCRYPT_N_MINIMUM) + " and " + str(SCRYPT_N_MAXIMUM) + "!"
	scrypt_n = inputlib.do_input_loop(inputlib.ask_integer, scrypt_n_input_args, scrypt_n_input_kwargs, error_message = scrypt_n_error_message)
	print()

	print("[master key memory factor]")
	print("this should be increased in the event of a major advance in RAM technology")
	print("it may be any positive non-zero integer; the default is " + str(DEFAULT_SCRYPT_R))
	scrypt_r_input_args = ("scrypt memory factor [def: " + str(DEFAULT_SCRYPT_R) + "]: ", )
	scrypt_r_input_kwargs = {"default": DEFAULT_SCRYPT_R, "verification_function": is_valid_r}
	scrypt_r_error_message = "memory factor must be a non-zero integer!"
	scrypt_r = inputlib.do_input_loop(inputlib.ask_integer, scrypt_r_input_args, scrypt_r_input_kwargs, error_message = scrypt_r_error_message)
	print()

	print("[master key paralellism factor]")
	print("this should be increased in the event of a major advance in CPU technology")
	print("it may be any positive non-zero integer; the default is " + str(DEFAULT_SCRYPT_P))
	scrypt_p_input_args = ("scrypt parallelism factor [def: " + str(DEFAULT_SCRYPT_P) + "]: ", )
	scrypt_p_input_kwargs = {"default": DEFAULT_SCRYPT_P, "verification_function": is_valid_p}
	scrypt_p_error_message = "parallelism factor must be a non-zero integer!"
	scrypt_p = inputlib.do_input_loop(inputlib.ask_integer, scrypt_p_input_args, scrypt_p_input_kwargs, error_message = scrypt_p_error_message)
	print()

	print()

	print("[master password]")
	print("the database's master password will be required on each launch")
	print("it should be as strong as possible, yet memorable")
	print("if lost, the database's contents will be *absolutely unrecoverable*")
	print()
	password = None
	while True:
		password = ask_database_password()
		if (password != None):
				print("please re-enter the master password you chose")
				verification = ask_database_password()
				if (verification == password):
					break
				else:
					print("passwords did not match!")
					print()
					continue
		else:
			print("database master password cannot be blank!")
			print()
	print()
	print()

	return (scrypt_n, scrypt_r, scrypt_p, password)

def ask_password_parameters():
	print()
	print("--- randomly generate password ---")
	print()

	print("length of the random password - this should be as long as possible")
	length_input_args = ("password length [def: " + str(DEFAULT_PASSWORD_LENGTH) + "]: ", )
	length_input_kwargs = {"default": DEFAULT_PASSWORD_LENGTH, "verification_function": is_valid_length}
	length_error_message = "password length must be a positive integer!"
	length = inputlib.do_input_loop(inputlib.ask_integer, length_input_args, length_input_kwargs, error_message = length_error_message)
	print()

	print("use digits in the random password? this should be enabled if possible")
	digits_input_args = ("use digits? " + bool_to_y_n(DEFAULT_PASSWORD_DIGITS) + ": ", )
	digits_input_kwargs = {"default": DEFAULT_PASSWORD_DIGITS}
	digits_error_message = "digits enabled must be a 'y' for yes, or a 'n' for no"
	digits = inputlib.do_input_loop(inputlib.ask_boolean, digits_input_args, digits_input_kwargs, error_message = digits_error_message)
	print()

	print("use special chars in the random password? this should be enabled if possible")
	special_input_args = ("use special characters? " + bool_to_y_n(DEFAULT_PASSWORD_SPECIAL_CHARACTERS) + ": ", )
	special_input_kwargs = {"default": DEFAULT_PASSWORD_SPECIAL_CHARACTERS}
	special_error_message = "special characters enabled must be a 'y' for yes, or a 'n' for no"
	special = inputlib.do_input_loop(inputlib.ask_boolean, special_input_args, special_input_kwargs, error_message = special_error_message)
	print()

	print("use spaces in the random password? this should be enabled if possible")
	spaces_input_args = ("use spaces? " + bool_to_y_n(DEFAULT_PASSWORD_DIGITS) + ": ", )
	spaces_input_kwargs = {"default": DEFAULT_PASSWORD_DIGITS}
	spaces_error_message = "spaces enabled must be a 'y' for yes, or a 'n' for no"
	spaces = inputlib.do_input_loop(inputlib.ask_boolean, spaces_input_args, spaces_input_kwargs, error_message = spaces_error_message)
	print()

	return (length, digits, special, spaces)

class DatabaseConsole(cmd.Cmd):
	intro = "password manager database prompt -- type 'help' for a list of commands\n"
	prompt = ">> "

	def do_get(self, line):
		"""Retrieve the record from the database that was stored under the given key
Usage: get <key> [--show]"""
		args = line.split()

		if (len(args) == 0) or (len(args) > 2): # the command must have 1 or 2 arguments
			return False

		show_result = False
		if len(args) == 2: # if there are 2 args
			if args[1].lower() == "--show": # the second one must be --show
				show_result = True
			else: # or the command's syntax is incorrect
				return False

		key = args[0]
		result = database.retrieve_record(key)
		if result is None:
			print("error: no record associated with that key!")
			return True

		if show_result:
			print("result: '" + result + "'")
		else:
			clipboard.copy(result)
			print("result successfully copied to clipboard")

		return True

	def do_set(self, line):
		"""Store a value in the database under the given key
If a second argument is not provided, a password will be randomly generated
Usage: set <key> [value]"""
		args = line.split()

		if (len(args) == 0) or (len(args) > 2): # the command must have 1 or 2 arguments
			return False

		key = args[0]
		value = None

		if len(args) == 2:
			value = args[1]
		elif len(args) == 1:
			length, digits, special_characters, spaces = ask_password_parameters()
			value = passwordlib.generate_password(length = length, digits = digits, special_characters = special_characters, spaces = spaces)

		success = database.store_record(key, value)
		if success:
			print("value successfully stored in the database")
		else:
			print("error: value already exists for this key!")
			# TODO: option to overwrite here
		return True

	def do_del(self, line):
		"""Delete the record from the database that was stored under the given key
Usage: del <key>"""
		args = line.split()

		if len(args) != 1: # the command must have 1 argument
			return False

		key = args[0]

		if not database.check_record(key):
			print("error: no record associated with that key!")
			return True

		print("please re-type the name of the key to be permanently deleted")
		confirmation = inputlib.ask_string("confirm: ")
		print()

		if confirmation == key:
			database.delete_record(key)
			print("key successfully removed from the database")
		else:
			print("error: confirmation mismatch -- no changes have been applied to the database!")

		return True

	def do_exit(self, line):
		"""Shut down the database and exit the program immediately
Usage: exit"""
		print("shutting down database...")
		database.close()
		sys.exit()

	def emptyline(self):
		print("type 'help' for a list of commands")

	def postcmd(self, success, line):
		if success is False:
			self.default(line)
		print()

def main():
	database_prompt = "database location [def: " + DEFAULT_DATABASE + "]: "
	database_file = inputlib.ask_string(database_prompt, default = DEFAULT_DATABASE)

	global database
	database = TinfoilDB(database_file)

	if not database.check_database_initialized():
		scrypt_n, scrypt_r, scrypt_p, password = ask_database_parameters()

		print("setting up database...")
		database.initialize_database(password = password, scrypt_n = (2 ** scrypt_n), scrypt_r = scrypt_r, scrypt_p = scrypt_p, aes_key_size = AES_KEY_SIZE, hmac_key_size = HMAC_KEY_SIZE)
		print("database successfully initialized!")
	else:
		print("database successfully loaded!")
	print()

	while True:
		password = ask_database_password()

		if password == None:
			print("master password cannot be blank!")
			print()
			continue

		if database.set_master_keys(password):
			print("database successfully unlocked!")
			break
		else:
			print("incorrect master password!")
			print()
	print()

	DatabaseConsole().cmdloop()

if __name__ == "__main__":
	main()
