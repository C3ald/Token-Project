import os
import functools
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

	def generate(self):
		""" Generates a new set of wallet keys """
		key = ECC.generate(curve='P-256')
		public = key.public_key().export_key(format='DER')
		private = key.export_key(format='DER')
		results = {'public key': public, 'private key': private}
		return results

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
	# def generate(self):
	# 	""" Generates a new set of wallet keys """
	# 	key = ECC.generate(curve='P-256')
	# 	protection = self.seed_gen()
	# 	public = key.public_key().export_key(format='PEM')
	# 	private = key.export_key(format='PEM', passphrase=protection, protection="PBKDF2WithHMAC-SHA1AndAES128-CBC")
	# 	results = {'public key': public, 'private key': private, 'protection':protection}
	# 	return results


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
	""" Encrypts the data on the transaction by using layers of encryption """

	def __init__(self):
		pass

	def make_onion_signature(self, transaction: dict):
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

		layers = 13
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
		sender_sets = encryption_keys
		receiver_sets = encryption_keys
		sender_sets[sender_sets.index(key)] = sender_set
		receiver_sets[receiver_sets.index(key)] = receiver_sets
		transaction['sender'] = sender
		transaction['receiver'] = receiver
		transaction.update(
		    {'sender set': sender_sets, 'receiver set': receiver_sets})
		return transaction

	def decrypt_and_verify_data(self, encryption_key: str, encrypted_data: dict):
		""" Decrypts the data """
		key = unhexlify(encryption_key)
		formated_data = self.format_data(encrypted_data['data'])
		nonce = unhexlify(formated_data['nonce'])
		cipher = AES.new(key, AES.MODE_EAX, nonce)
		cipher_text = unhexlify(formated_data['encrypted data'])
		tag = unhexlify(formated_data['tag'])
		try:
			plain_text = cipher.decrypt_and_verify(cipher_text, tag)
			return plain_text.decode()
		except ValueError:
			print('invalid')
			None

	def decrypt_encryption_key(self, publickey: str, encrypted_decryption_key_data: str):
		encrypted_pub = hashlib.sha256(publickey.encode()).hexdigest()
		decryption_key = encrypted_decryption_key_data.replace(encrypted_pub, '')
		return decryption_key.hex()

	def combine(self, publickey: str, encryption_key: str):
		encrypted_pub = hashlib.sha256(publickey.encode()).hexdigest()
		random_place = random.randint(0, len(encrypt_key))
		new_string = encryption_key[:random_place] + \
		    encrypted_pub + encryption_key[random_place:]
		return new_string

	def encrypt(self, data: str, key=None):
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
		return {'data': f'{cipher.nonce.hex()}+{encrypted_data.hex()}+{tag.hex()}', 'key': decrypt_key}

	def format_data(self, data: str):
		result = data.split('+')
		result = {'nonce': result[0], 'encrypted data': result[1], 'tag': result[2]}
		return result

	def generate_new_key(self):
		key = get_random_bytes(32)
		cipher = AES.new(key, AES.MODE_EAX)
		cipher = cipher.hexdigest()
		return cipher


class Ring_example:
    """ECC Implementation reference: https://medium.com/asecuritysite-when-bob-met-alice/ring-signatures-and-anonymisation-c9640f08a193"""
    """
class ring:
    def __init__(self, k, L=1024):
        self.k = k
        self.l = L
        self.n = len(list(k))
        self.q = 1 << (L - 1)

    def sign(self, m, z):
        self.permut(m)
        s = [None] * self.n
        u = random.randint(0, self.q)
        c = v = self.E(u)
        for i in (list(range(z+1, self.n)) + list(range(z))):
            s[i] = random.randint(0, self.q)
            e = self.g(s[i], self.k[i].e, self.k[i].n)
            v = self.E(v^e)
            if (i+1) % self.n == 0:
                c = v
        s[z] = self.g(v^u, self.k[z].d, self.k[z].n)
        return [c] + s

    def verify(self, m, X):
        self.permut(m)
        def _f(i):
            return self.g(X[i+1], self.k[i].e, self.k[i].n)
        y = list(map(_f, list(range(len(X)-1))))
        def _g(x, i):
            return self.E(x^y[i])
        r = reduce(_g, list(range(self.n)), X[0])
        return r == X[0]

    def permut(self, m):
        self.p = int(hashlib.sha1(m.encode()).hexdigest(),16)
   #     sha1(s.encode(encoding)).hexdigest()

    def E(self, x):
        msg = '%s%s' % (x, self.p)
        return  int(hashlib.sha1(msg.encode()).hexdigest(),16)

    def g(self, x, e, n):
        q, r = divmod(x, n)
        if ((q + 1) * n) <= ((1 << self.l) - 1):
            rslt = q * n + pow(r, e, n)
        else:
            rslt = x
        return rslt

size = 4
msg1="Hello"
msg2="Hello2"



def _rn(_):
  return Crypto.PublicKey.RSA.generate(1024, os.urandom)

print(("Message is:",msg1))
key = list(map(_rn, list(range(size))))
r = ring(key)
for i in range(size):
    s1 = r.sign(msg1, i)
    s2 = r.sign(msg2, i)
    if (i==1):
      print(("Signature is", s1))
      print(("Signature verified:",r.verify(msg1, s1)))
      print(("Signature verified (will fail):",r.verify(msg2, s1)))
#    assert r.verify(msg1, s1) and r.verify(msg2, s2) and not r.verify(msg1, s2)

    """

    def __init__(self):
        """
            1.  generate: k=Hash(message)
            2.	generate random value: u
            3. Encrypt u to give v=Ek(u)
            4. For each person (apart from the sender):
            4.1 Calculate e=sPii(modNi) and where si is the random number generated for the secret key of the ith party, and Pi is the public key of the party.
            4.2 Calculate v=v⊕e
            5. For the signed party (z), calculate sz=(v⊕u)d(modNz) and where d is the secret key of the signing party.	We will end up with the signature (v=Ek(u)), and which completes the ring.
        """
        """ Transactions need to be asymmetrical and only turned into ring signatures after verification."""
        self.max_size = 14
            
            


if __name__ == '__main__':
	# wallet = Wallet_generation()
 	# keys = wallet.generate()
	# pub_key = keys['public key']
	# priv_key = keys['private key']
	# print(pub_key)
	# print(priv_key)
	# signer = Signatures()
	# signature = signer.sign(priv_key, 'Alice')
	# #print(signature)
	# valid = signer.verify(pub_key, 'Alice', signature)
	# #print(valid)
	# onion = Onion_Signatures()
	# encrypt_key = onion.generate_new_key()
	# print({'encrypt key':encrypt_key})
	# key_combined = onion.combine('Alice', encrypt_key)
	# print({'combined key':key_combined})
	# encrypted_data = onion.encrypt('example', encrypt_key) #Encrypts data using the encryption key
	# print({'encrypted data':encrypted_data})
	# #decrypt = onion.decrypt('Alice', key)
	# decrypted_data = onion.decrypt_and_verify_data(encrypt_key, encrypted_data) # decrypts the data
	# print(decrypted_data)
	# #print(decrypt)
	size = 17