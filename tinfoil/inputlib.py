
def ask_string(prompt, default = None, verification_function = None):
	user_input = input(prompt)
	if not user_input:
		return default
	elif not verification_function is None: # if verification function specified
		if not verification_function(user_input): # if verification fails
			return None # return none
	return user_input

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

def ask_boolean(prompt, default = None):
	user_input = input(prompt)
	if not user_input:
		return default

	input_lower = user_input.lower()
	if input_lower == "y":
		return True
	elif input_lower == "n":
		return False
	else:
		return None

def do_input_loop(input_function, args, kwargs, error_message = None):
	while True:
		result = input_function(*args, **kwargs)
		if (result != None):
			return result
		elif not error_message is None:
			print(error_message)
			print()
