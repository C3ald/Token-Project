from cryptography.fernet import Fernet
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
class Encrypt_and_Decrypt():
	""" Encryption and decryption of wallets to ensure security in the GUI wallet and while not in use with the GUI wallet """
	def __init__(self):
		pass
	def key(self,password:str):
		""" Encodes the key into bytes """
		encoded_password = password.encode()
		salt = b'\xfdJ\x99\xb7\xc3\x89hN\x9d\xa0\xa5\xc7\xb2J\x9c\x8f'
		kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
		key = base64.urlsafe_b64encode(kdf.derive(encoded_password))
		return key
	
	def write_to_file(self, file:str, data:str):
		""" writes to the file """
		encoded_data = data.encode()
		open_file = open(file, 'wb')
		with open_file as f:
			f.write(encoded_data)
		return file

	def encrypt_file(self, password:str, file):
		""" encrypts the file """
		key = self.key(password=password)
		with open(file, 'rb') as f:
			data = f.read()
		fernet = Fernet(key)
		encrypted = fernet.encrypt(data)
		with open(f'{file}.encrypted', 'wb') as f:
			f.write(encrypted)
		result = f'{file}.encrypted'
		return {'encrypted file': result, 'message': 'You can delete the original file '}
	
	def decrypt_file(self, password:str, encrypted_file):
		""" Decrypts the encrypted file """
		key = self.key(password)
		with open(encrypted_file, 'rb') as f:
			data = f.read()
		fernet = Fernet(key)
		decrypted = fernet.decrypt(data).decode()
		return decrypted
	def encrypt_text(self, password:str, text):
		""" encrypts the file """
		key = self.key(password=password)
		fernet = Fernet(key)
		encrypted = fernet.encrypt(data)
		return encrypted.decode()
	
	def decrypt_text(self, password:str, encrypted_text:str):
		""" Decrypts the encrypted file """
		key = self.key(password)
		fernet = Fernet(key)
		decrypted = fernet.decrypt(encrypted_text.encode()).decode()
		return decrypted

if __name__ == '__main__':
	Encrypt_and_Decrypt()