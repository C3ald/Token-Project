from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from Cryptodome.Hash import SHA512
from Cryptodome.Random import *
from Cryptodome.Cipher import AES
import uuid
import string
import random
from binascii import unhexlify
import hashlib
import codecs

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


class Wallet_generation:
	""" Wallet Generation """
	def __init__(self):
		pass


	def generate(self):
		""" Generates a new set of wallet keys """
		key = ECC.generate(curve='P-256')
		public = key.public_key().export_key(format='PEM')
		private = key.export_key(format='PEM')
		results = {'public key': public, 'private key': private}
		return results
	


class Signatures:
	""" Signs data """
	def __init__(self):
		pass

	def sign(self, private_key, receiver):
		""" signs the transaction by using the receiver's public key as the encrypted data """
		private = ECC.import_key(private_key)
		# id = str(uuid.uuid4())
		data = receiver.encode()
		hashed_id = SHA512.new(data)
		
		signer = DSS.new(private, 'fips-186-3')
		signature = signer.sign(hashed_id).hex()
		return signature


	def verify(self, public_key, receiver, signature):
		""" Verifies the signature returns True if signature is valid and False if the signature is invalid"""
		public = ECC.import_key(public_key)
		hashed_id = SHA512.new(receiver.encode())
		un_hexed = unhexlify(signature)
		verifier = DSS.new(public, 'fips-186-3')
		try:
			verifier.verify(hashed_id, un_hexed)
			return True
		except:
			return False
class Onion_Signatures:
	""" Encrypts the data on the transaction """
	def __init__(self):
		pass

	def make_signature(self, transaction):
		""" picks a random number of signatures to add to the current one """
		# Miner generates a random number of keys to use for encryption and the sender and the receiver encrypt their own sets of the miner's keys
		# Miner's randomly generated keys encrypt the sender and receiver
		# add keys used for encryption to a new part called encoding and combine the sender's publickey and the key for decrypting with it and do the same with receiver in a different set
		# make it look like this: {'sender_encoding': sender+decryptionkey, 'receiver_encding': receiver+decryptionkey}
		sender = transaction['sender']
		receiver = transaction['receiver']
		amount = transaction['amount']
		signature_of_sender = transaction['signature']



	# def combine(self, publickey, decryption_key):
	# 	""" Combines the sender and receiver with the decryption key, hashes the sender and receiver then combines it with the decryption key """
	# 	encrypted_key = hashlib.sha256(publickey.encode()).hexdigest()
	# 	encrypted_key = bytes(encrypted_key.encode())
	# 	encrypted_key = int.from_bytes(encrypted_key, 'big')
	# 	encrypted_decryption = bytes(decryption_key.encode())
	# 	encrypted_decryption = int.from_bytes(encrypted_decryption, 'big')
	# 	print(encrypted_decryption)
	# 	algorithm = encrypted_key * encrypted_decryption
	# 	print(algorithm)
	# 	result = hex(algorithm)
	# 	return result


	# def decrypt(self, publickey, encrypted_data):
	# 	encrypted_key = hashlib.sha256(publickey.encode()).hexdigest()
	# 	encrypted_key = bytes(encrypted_key.encode())
	# 	encrypted_public = int.from_bytes(encrypted_key, 'big')
	# 	encrypted_data = bytes.fromhex(encrypted_data[2:])
	# 	encrypted_data = int.from_bytes(encrypted_data, 'big')
	# 	algorithm = encrypted_data / encrypted_public
	# 	print(algorithm)
	# 	to_hex = hex(int(algorithm))[2:]
	# 	#print(to_hex)
	# 	to_bytes = bytes.fromhex(to_hex)
	# 	#to_bytes = unhexlify(to_int)
	# 	return to_bytes.decode()

	def decrypt(self, publickey:str, encrypted_data:str):
		encrypted_pub = hashlib.sha256(publickey.encode()).hexdigest()
		decryption_key = encrypted_data.replace(encrypted_pub, '')
		return decryption_key


	def combine(self, publickey, encryption_key):
		encrypted_pub = hashlib.sha256(publickey.encode()).hexdigest()
		random_place = random.randint(0, len(encrypt_key))
		new_string = encryption_key[:random_place] + encrypted_pub + encryption_key[random_place:]
		return new_string



	def encrypt(self, data:str, key=None):
		encoded = data.encode()
		if key == None:
			key = self.generate_new_key()
		cipher = AES.new(key, AES.MODE_EAX)
		encrypted = cipher.encrypt_and_digest(data)
		return encrypted
		


	def generate_new_key(self):
		key = get_random_bytes(32)
		cipher = AES.new(key, AES.MODE_EAX)
		cipher = cipher.hexdigest()
		return cipher



if __name__ == '__main__':
	wallet = Wallet_generation()
	keys = wallet.generate()
	pub_key = keys['public key']
	priv_key = keys['private key']
	print(pub_key)
	print(priv_key)
	signer = Signatures()
	signature = signer.sign(priv_key, 'Alice')
	#print(signature)
	valid = signer.verify(pub_key, 'Alice', signature)
	#print(valid)
	onion = Onion_Signatures()
	encrypt_key = onion.generate_new_key()
	print(encrypt_key)
	key = onion.combine('Alice', encrypt_key)
	print(key)
	decrypt = onion.decrypt('Alice', key)
	
	print(decrypt)