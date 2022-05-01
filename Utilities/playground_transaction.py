from Crypto.PublicKey import ECC
from wallet import Wallet
import base64
import secrets
from Crypto.Cipher import AES
import hashlib, secrets, binascii
from tinyec import registry

wallet = Wallet()

DATA = {'sender': 'Bob', 'receiver': 'Jen', 'amount': 100.0}

key1 = ECC.generate(curve='P-256')
key2 = ECC.generate(curve='P-256')


def generate_priv_key():
	""" generates private key """
	password = wallet.password()
	with open('priv-keys_pem.pem', 'w') as f:
		""" key generation """
		key = key1.export_key(format='PEM', passphrase=password, protection='PBKDF2WithHMAC-SHA1AndAES128-CBC')
		f.write(key)
		f.close()
		return {'private key': key, 'passphrase': password}



# Create public key
def generate_pub_key():
	""" generates public key """

	with open('pub-keys_pem.pem', 'w') as f:
		""" Write the public key """
		priv_key = key1
		pubkey = priv_key.public_key().export_key(format='PEM')
		f.write(pubkey)
		return pubkey

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

def encrypt_message(key, message):
	""" Encrypts the message """
	curve = registry.get_curve('brainpoolP256r1')

	ciphertextPrivKey = secrets.randbelow(curve.field.n)
	sharedECCKey = ciphertextPrivKey * key
	secretKey = ecc_point_to_256_bit_key(sharedECCKey)
	ciphertext, nonce, authTag = (message, secretKey)
	ciphertextPubKey = ciphertextPrivKey * curve.g
	return (ciphertext, nonce, authTag, ciphertextPubKey)


def decrypt_message(filename, message):
	""" Decrypts the  """

if __name__ == '__main__':
	privkey_and_passphrase = generate_priv_key()
	privkey = privkey_and_passphrase['private key']
	passphrase = privkey_and_passphrase['passphrase']
	pubkey = generate_pub_key()
	encrypt_message(key=pubkey, message=DATA)