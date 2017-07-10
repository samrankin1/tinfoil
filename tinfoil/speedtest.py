#!/bin/python3

import time
import math
import os

import scrypt

DEFAULT_MAX_RAM = 6
DEFAULT_MAX_TIME = 5

MINIMUM_N = 14

DEFAULT_R = 8

def is_positive_integer(number):
	return (number > 0)

def ask_integer(prompt, default = None, verification_function = None):
	user_input = input(prompt)
	if not user_input:
		return default

	parsed_input = None
	try:
		parsed_input = int(user_input)
	except ValueError:
		return None

	if not verification_function is None:
		if not verification_function(parsed_input):
			return None

	return parsed_input

def do_input_loop(input_function, args, kwargs, error_message = None):
	while True:
		result = input_function(*args, **kwargs)
		if (result != None):
			return result
		elif not error_message is None:
			print(error_message)
			print()

def ask_parameters():
	print("--- scrypt parameter determination ---")
	print()
	print("higher values will always make your database more secure") # this is not always true
	print()

	# print("what is the maximum amount of RAM you can guarantee will be available when opening your database?")
	max_ram_input_args = ("maximum RAM usage in GB [def: " + str(DEFAULT_MAX_RAM) + "]: ", )
	max_ram_input_kwargs = {"default": DEFAULT_MAX_RAM, "verification_function": is_positive_integer}
	max_ram_error_message = "maximum RAM usage must be a positive integer!"
	max_ram = do_input_loop(ask_integer, max_ram_input_args, max_ram_input_kwargs, error_message = max_ram_error_message)
	# print()

	# print("how many seconds are you willing to wait for your database to open?")
	max_time_input_args = ("maximum wait time in seconds [def: " + str(DEFAULT_MAX_TIME) + "]: ", )
	max_time_input_kwargs = {"default": DEFAULT_MAX_TIME, "verification_function": is_positive_integer}
	max_time_error_message = "maximum wait time must be a positive integer!"
	max_time = do_input_loop(ask_integer, max_time_input_args, max_time_input_kwargs, error_message = max_time_error_message)
	print()

	return (max_ram, max_time)


def get_max_N(max_ram):
	# https://stackoverflow.com/a/30308723
	return math.floor(math.log2((max_ram * (10 ** 9)) // (128 * DEFAULT_R)))

def main():
	max_ram, max_time = ask_parameters()

	password = os.urandom(40) # 40 character placeholder password
	salt = os.urandom(8) # standard 8-byte salt

	max_n = get_max_N(max_ram)
	print("checking N values from " + str(MINIMUM_N) + " through " + str(max_n) + "...")
	for n in range(MINIMUM_N, max_n):
		n_exponent = 2 ** n
		start = time.time()
		scrypt.hash(password = password, salt = salt, N = n_exponent, r = DEFAULT_R, p = 1, buflen = 32)
		end = time.time()
		elapsed = round((end - start), 2)

		if elapsed > max_time:
			optimal_n = (n - 1)

			print()
			if optimal_n >= MINIMUM_N:
				print("result: optimal N = '" + str(optimal_n) + "'")
			else:
				print("error: no valid values for N! please increase RAM or time allowance!")
			print()

			break
		else:
			print("N = " + str(n) + "; time = " + str(elapsed) + "s")

if __name__ == "__main__":
	main()
