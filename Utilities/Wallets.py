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
import requests as r

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


class Wallet_generation:
	""" Wallet Generation """
	def __init__(self):
		pass

	def seed_gen(self, password=None):
		if not password:
			word_file = "./seeds.txt"
			words = open(word_file).read().splitlines()
			num_of_seeds = 8
			seeds = random.sample(words, num_of_seeds)
			seed = ' '.join(seeds)
		else:
			seed = password
		print(seed)
		return seed
	def generate(self):
		""" Generates a new set of wallet keys """
		key = ECC.generate(curve='P-256')
		protection = self.seed_gen()
		public = key.public_key().export_key(format='PEM')
		private = key.export_key(format='PEM', passphrase=protection, protection="PBKDF2WithHMAC-SHA1AndAES128-CBC")
		results = {'public key': public, 'private key': private, 'protection':protection}
		return results
	


class Signatures:
	""" Signs data """
	def __init__(self):
		pass

	def sign(self, private_key, receiver, passphrase:str):
		""" signs the transaction by using the receiver's public key as the encrypted data """
		private = ECC.import_key(private_key, passphrase=passphrase,)
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
	""" Encrypts the data on the transaction by using layers of encryption """
	def __init__(self):
		pass

	def make_onion_signature(self, transaction:dict):
		""" encrypts all the transaction data """
		# Miner generates a random number of keys to use for encryption and the sender and the receiver encrypt their own sets of the miner's keys
		# Miner's randomly generated keys encrypt the sender and receiver
		# add keys used for encryption to a new part called encoding and combine the sender's publickey and the key for decrypting with it and do the same with receiver in a different set
		# make it look like this: {'sender_encoding': sender + decryptionkey, 'receiver_encding': receiver + decryptionkey}
		sender = transaction['sender']
		receiver = transaction['receiver']
		amount = transaction['amount']
		signature_of_sender = transaction['signature']
		encryption_keys = []
		
		
		layers = random.randint(5, 8)
		for x in ranage(layers):
			key = self.generate_new_key()
			sender = str(sender)
			receiver = str(receiver)
			signature_of_sender = str(signature_of_sender)
			sender = self.encrypt(sender, key=key)
			receiver = self.encrypt(receiver, key=key)
			if len(encryption_keys) == 0:
				encryption_keys.append(key)
			else:
				for used_key in encryption_keys:
					encrypted_key = self.encrypt(used_key, key)
					encryption_keys[encryption_keys.index(used_key)] = encrypted_key
				encryption_keys.append(key)
		sender_set = self.combine(sender, key)
		receiver_set = self.combine(receiver, key)
		# encryption_keys[encryption_keys.index(key)]
		sender_sets = encryption_keys
		receiver_sets = encryption_keys
		sender_sets[sender_sets.index(key)] = sender_set
		receiver_sets[receiver_sets.index(key)] = receiver_sets

		transaction['sender'] = sender
		transaction['receiver'] = receiver
		transaction.update({'sender set': sender_sets, 'receiver set': receiver_sets})
		return transaction
		



			




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


	def decrypt_and_verify_data(self, encryption_key:str, encrypted_data:dict):
		""" Decrypts the data """
		key = unhexlify(encryption_key)
		formated_data = self.format_data(encrypted_data['data'])
		nonce = unhexlify(formated_data['nonce'])
		cipher = AES.new(key, AES.MODE_EAX, nonce)
		cipher_text =  unhexlify(formated_data['encrypted data'])
		tag = unhexlify(formated_data['tag'])
		try:
			plain_text = cipher.decrypt_and_verify(cipher_text, tag)
			return plain_text.decode()
		except ValueError:
			print('invalid')
			None

	def decrypt_encryption_key(self, publickey:str, encrypted_decryption_key_data:str):
		encrypted_pub = hashlib.sha256(publickey.encode()).hexdigest()
		decryption_key = encrypted_decryption_key_data.replace(encrypted_pub, '')
		# key = AES.new(decryption_key, AES.MODE_EAX)
		# plain_text = key.decrypt_and_verify(encrypted_data)
		return decryption_key.hex()


	def combine(self, publickey:str, encryption_key:str):
		encrypted_pub = hashlib.sha256(publickey.encode()).hexdigest()
		random_place = random.randint(0, len(encryption_key))
		new_string = encryption_key[:random_place] + encrypted_pub + encryption_key[random_place:]
		return new_string



	def encrypt(self, data:str, key=None):
		encoded = data.encode()
		if key == None:
			key = self.generate_new_key()
			decrypt_key = key
		else:
			decrypt_key = None
		data = data.encode()
		key = unhexlify(key)
		cipher = AES.new(key, AES.MODE_EAX)
		encrypted_data, tag = cipher.encrypt_and_digest(data)
		return {'data':f'{cipher.nonce.hex()}+{encrypted_data.hex()}+{tag.hex()}', "decryption key": key.hex()}
	
	def format_data(self, data:str):
		result = data.split('+')
		result = {'nonce': result[0], 'encrypted data': result[1], 'tag': result[2]}
		return result



	def generate_new_key(self):
		key = get_random_bytes(32)
		cipher = AES.new(key, AES.MODE_EAX)
		cipher = cipher.hexdigest()
		return cipher



def main_test():
	wallet = Wallet_generation()
	keys = wallet.generate()
	pub_key = keys['public key']
	priv_key = keys['private key']
	protection = keys['protection']
	print(pub_key)
	print(priv_key)
	signer = Signatures()
	signature = signer.sign(priv_key, 'Alice', passphrase=protection)
	#print(signature)
	valid = signer.verify(pub_key, 'Alice', signature)
	#print(valid)
	onion = Onion_Signatures()
	encrypt_key = onion.generate_new_key()
	print(f"encryption key: {encrypt_key}")
	key_combined = onion.combine('Alice', encrypt_key)
	print(key_combined)
	encrypted_data = onion.encrypt('example', encrypt_key) #Encrypts data using the encryption key
	print(f"encrypted data:{encrypted_data}")
	#decrypt = onion.decrypt('Alice', key)
	decrypted_data = onion.decrypt_and_verify_data(encrypt_key, encrypted_data) # decrypts the data
	print(f"decrypted data: {decrypted_data}")
	#print(decrypt)
if __name__ == "__main__":
	main_test()