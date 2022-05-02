from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from Cryptodome.Hash import SHA512
import uuid
import string
import random
from binascii import unhexlify


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

	def make_signature(self, signature, blockchain):
		""" picks a random number of signatures to add to the current one """
		# Miner generates a random number of keys to use for encryption and the sender and the receiver encrypt their own sets of the miner's keys
		# Miner's randomly generated keys encrypt the sender and receiver
		# add keys used for encryption to a new part called encoding and combine the sender's publickey and the key for decrypting with it and do the same with receiver in a different set
		# make it look like this: {'sender_encoding': sender+decryptionkey, 'receiver_encding': receiver+decryptionkey}


	def convert_signature_to_list(self, signature):
		list_sign = list(signature)
		return list_sign



if __name__ == '__main__':
	wallet = Wallet_generation()
	keys = wallet.generate()
	pub_key = keys['public key']
	priv_key = keys['private key']
	print(pub_key)
	print(priv_key)
	signer = Signatures()
	signature = signer.sign(priv_key, 'Alice')
	print(signature)
	valid = signer.verify(pub_key, 'Alice', signature)
	print(valid)