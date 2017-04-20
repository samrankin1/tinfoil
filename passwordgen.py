import string
import random

LETTERS = [c for c in string.ascii_letters]
DIGITS = [c for c in string.digits]
SPECIAL_CHARACTERS = [c for c in string.punctuation]
SPACES = [" "]

def generate_password(length = 20, digits = True, special_characters = True, spaces = True):
	character_space = LETTERS[:]
	if digits:
		character_space += DIGITS
	if special_characters:
		character_space += SPECIAL_CHARACTERS
	if spaces:
		character_space += SPACES

	result = ""
	for _ in range(length):
		result += random.SystemRandom().choice(character_space)

	return result