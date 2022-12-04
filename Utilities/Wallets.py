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

from binascii import unhexlify,hexlify
import hashlib
import codecs
import requests as r
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

      # test
class Wallet_generation:
	""" Wallet Generation """

	def __init__(self):
		pass

	def generate(self):
		""" Generates a new set of wallet keys """
		ecc = ECC
		seed = self.seed_gen().encode()
		encoded_seed = int.from_bytes(seed, 'big')
		ecc.d = encoded_seed
		key = ecc.generate(curve='P-256')
		public = key.public_key().export_key(format='DER')
		private = key.export_key(format='DER')
		results = {'public key': hexlify(public).decode(), 'private key': hexlify(private).decode(), 'seed': seed.decode()}
		return results

	def seed_gen(self, password=None):
		if not password:
			word_file = "./seeds.txt"
			words = open(word_file).read().splitlines()
			num_of_seeds = 23
			seeds = random.sample(words, num_of_seeds)
			seed = ' '.join(seeds)
		else:
			seed = password
		# print(seed)
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
	wallet = Wallet_generation()
	keys = wallet.generate()
	print(keys)
