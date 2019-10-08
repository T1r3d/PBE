#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""A PBE pymode for private use."""

__author__ = "t1r3d"


import os
import base64
import argparse
from secrets import SystemRandom

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class PBE(object):
	"""Password Based Encryption Pymode.

	Based on cryptography.

	Attributes:

	"""

	def __init__(self, filename, password="P@55w0rd"):
		"""Init the PBEr.
	
		Args:
			filename: The file to be encrypted/decrypted.
			password: The password used to generate the symmetric key uesd in AES
		
		Returns:
			None
		
		Raises:
			None	
		"""
		self.password = password.encode("utf-8")
		self.filename = filename

	def encrypt(self):
		"""Encrypt the private key."""

		with open(self.filename, "rb") as f:
			plain_text = f.read()
		salt = os.urandom(64)	
		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA512(),
			length=32,
			salt=salt,
			iterations=10000,
			backend=default_backend()
			)
		key = kdf.derive(self.password)
		nonce  = os.urandom(12)
		aesgcm = AESGCM(key)
		cipher_text = aesgcm.encrypt(
			nonce=nonce,
			data=plain_text,
			associated_data=None
			)

		# Store the meta data(salt, nonce, cipher_text) in base64

		cipher_list = map(base64.b64encode, [salt, nonce, cipher_text])
		joint_cipher_text = ".".join([_.decode() for _ in cipher_list])
		enc_filename = self.filename + ".enc"
		with open(enc_filename, "wb") as ef:
			ef.write(joint_cipher_text.encode("utf-8"))
		print("\033[1;32;40m[+] Encrypt Success! \033[0m \n[*] THe encrypted file stored as %s"%enc_filename)

		return None

	def decrypt(self):
		"""Decrypt the private key."""

		with open(self.filename, "rb") as f:
			joint_cipher_text = f.read().decode()  # Turn bytes to str.
		salt, nonce, cipher_text = map(base64.b64decode, joint_cipher_text.split("."))
		kdf = PBKDF2HMAC(
			algorithm=hashes.SHA512(),
			length=32,
			salt=salt,
			iterations=10000,
			backend=default_backend()
			)
		key = kdf.derive(self.password)
		aesgcm = AESGCM(key)
		plain_text = aesgcm.decrypt(
			nonce=nonce,
			data=cipher_text,
			associated_data=None
			)
		dec_filename = self.filename[:-4] + ".dec"
		with open(dec_filename, "wb") as df:
			df.write(plain_text)
		print("\033[1;32;40m[+] Decrypt Success! \033[0m \n[*] THe decrypted file stored as %s"%dec_filename)

		return None


def banner():
	"""Print banner."""

	print(r""" __  __       _____  ____  ______ 
|  \/  |     |  __ \|  _ \|  ____|
| \  / |_   _| |__) | |_) | |__   
| |\/| | | | |  ___/|  _ <|  __|  
| |  | | |_| | |    | |_) | |____ 
|_|  |_|\__, |_|    |____/|______|
         __/ |                    
        |___/                        Author: t1r3d """)
	print("\n\n")


def init():
	"""Init the argpaser.
	
	Returns:
		Arguments Object.	
	"""

	parser = argparse.ArgumentParser(description='A PBE pymode for personal use')
	group = parser.add_mutually_exclusive_group()
	group.add_argument("-e", "--encrypt", action="store_true", dest="encrypt", help="Set the encryption mode.")
	group.add_argument("-d", "--decrypt", action="store_true", dest="decrypt", help="Set the decryption mode.")
	parser.add_argument("-p", "--passwd", dest="password", required=True, help="The password of the encryption/decryption file.")
	parser.add_argument("filename", help="The file to be encrypted/decrypted.")
	args = parser.parse_args()

	return args


def main():
	banner()
	args = init()
	if args.encrypt and args.decrypt:
		print("\033[1;31m[-] Error: \033[0mIt's forbbiden to set both encryption mode and decryption mode.")
		exit()
	elif not args.encrypt and not args.decrypt:
		print("\033[1;31m[-] Error: \033[0mEither encryption mode or decryption mode must be choosen.")
	if args.encrypt:
		pbe = PBE(args.filename, args.password)
		pbe.encrypt()
	elif args.decrypt:
		pbe = PBE(args.filename, args.password)
		pbe.decrypt()


if __name__ =="__main__":
	main()

# TODO(t1r3d): Error handling(Invalid password, hidden the password while input) and more algorithm options.