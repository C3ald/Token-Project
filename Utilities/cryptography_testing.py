#from types import NoneType
from passlib.hash import pbkdf2_sha256
import hashlib
import random
import base64

import string
import requests as r







class Algs():
	""" algorithms for the blockchain """
	def __init__(self):
		self.difficulty = 0
		self.fee = 0.0000001
		self.list_count = []
		self.count = str(len(self.list_count))
		self.new_amount = 0
		self.amount = 100

	
	def difficulty_increase(self, chain:list, nodes_list):
		""" difficulty of a block """
 
		self.list_count = ['0']
		number_of_nodes = 0
		interval = 0
		self.amount = self.amount_change(chain=chain)
		for block in chain:
			index = block['index']
			if index % 20000 == 0 and index != 0:
				self.amount = self.amount / 2
				if len(self.list_count) != 9:
					self.list_count.append('0')
		for nodes in nodes_list:
			try:
				node = nodes['node']
				test = r.get(f'http://{node}/get_the_chain')
				if test.status_code == 200:
					number_of_nodes = number_of_nodes + 1
			except:
				None
			for x in range(number_of_nodes):
				if number_of_nodes != 0 and x % 100000 == 0:
					interval = interval + 1.001
			
			
		if interval != 0:
			self.amount = self.amount / interval



		self.count = len(self.list_count)
		self.difficulty = "".join(self.list_count)
		return self.difficulty
		

	def network_fee(self, amount):
		""" the fee for transactions """
		self.fee = 0.0000001
		self.new_amount = 0

		self.new_amount = amount - self.fee
		return self.new_amount
	
	

	def amount_change(self, chain):
		""" the change in block reward """
		if len(chain) > 1:
			i = -1
			transaction = chain[i]['data']

			new_amount = 100
			if len(transaction) > 1:
				for data in transaction:
					new_amount = new_amount + self.fee
				new_amount = new_amount - self.fee

		else:
			new_amount = 100
		self.amount = new_amount
		return self.amount
	
algs = Algs()
class Ring_CT():
	""" Ring signatures """
	def __init__(self):
		pass
	def make_ring_sign(self, blockchain: list, primary_address: string):
		""" makes the signature """
		ring_sign = [primary_address]
		number_of_signatures = self.calculate_number_signatures(blockchain)
		x = 0
		while x != number_of_signatures:


			transaction = Decoy_addresses().decoy_keys()['publickey']
			
			ring_sign.append(transaction)
			x = x+1
		ring_sign = self.shuffle(ring_sign)
		return ring_sign

	def calculate_number_signatures(self, blockchain):
		""" Calculates the number of decoy transactions """
		number_of_decoy_addr = random.randint(4,5)
		return number_of_decoy_addr

	def shuffle(self, ring_signitures):
		""" Shuffles the signitures """
		transactions = ring_signitures
		length = range(len(transactions))
		for i in length:
			j = random.randint(0, i)
			transactions[i], transactions[j] = transactions[j], transactions[i]
		return transactions


	def ring_sign(self, blockchain:list, primary_address:string):
		""" Automates ring signatures """
		signatures = self.make_ring_sign(blockchain, primary_address)
		new_transactions = self.shuffle(signatures)
		return new_transactions









class primary_addresses():
	""" makes your primary address for receiving Tokens and can verify the primary address """
	def __init__(self):
		pass
	def make_primary_address(self, public_view):
		""" Makes the primary address and encodes it"""
		data = public_view
		encoded_data = data.encode()
		encoded_data = base64.b64encode(encoded_data)
		encoded_primary = hashlib.sha256(encoded_data).hexdigest()
		return encoded_primary


	def decode_primary_address(self,primary_address, public_view):
		data = public_view 
		encoded_data = data.encode()
		encoded_data = base64.b64encode(encoded_data)
		hashed_data = hashlib.sha256(encoded_data).hexdigest()
		if hashed_data == primary_address:
			return True
		else:
			return False





class Make_Keys():
	""" creates wallet keys or addresses """
	def __init__(self):
		pass

	def make_password(self):
		characters = string.ascii_letters + string.punctuation  + string.digits
		passwd =  "".join(random.choice(characters) for x in range(90))
		return str(passwd)


	def make_spend_view_receive_keys(self):
		password = str(self.make_password())
		priv_spend = str(pbkdf2_sha256.hash(password))
		priv_spend = priv_spend.replace('$pbkdf2-sha256$29000$', '')
		pub_spend = str(pbkdf2_sha256.hash(priv_spend))
		pub_spend = pub_spend.replace('$pbkdf2-sha256$29000$', '')
		view_key = str(pbkdf2_sha256.hash(priv_spend))
		view_key = view_key.replace('$pbkdf2-sha256$29000$', '')
		prime_addr = primary_addresses().make_primary_address(view_key)
		return {'private spend key': priv_spend, 'public spend key': pub_spend, 'view key': view_key, 'primary address': prime_addr, 'seed for wallet': password}


	def make_stealth_keys(self, primary_address):
		stealth_address = str(pbkdf2_sha256.hash(primary_address))
		stealth_address = stealth_address.replace('$pbkdf2-sha256$29000$', '')
		return stealth_address

	

class Check_Wallet_Balance():
	""" Checks Balance and the validity of wallet addresses """
	def __init__(self):
		self.stealth_addresses = []
		self.transactions = []
	def verify_stealth_keys(self, stealth_key, primary_address):
		full_stealth_address = '$pbkdf2-sha256$29000$'+stealth_key
		verify = pbkdf2_sha256.verify(primary_address, full_stealth_address)
		return verify
	

	def stake_check(self,receiver_key, blockchain):
		chain = blockchain
		prime_addr = receiver_key
		positive_balance = self.receiver_check(prime_addr, chain)
		negative_balance = self.sender_check(prime_addr, chain)
		balance = positive_balance - negative_balance
		return balance







	def balance_check(self, public_view_key, blockchain, transaction=None):
		address = public_view_key
		chain = blockchain

		fake_BC = transaction
		self.transactions = []
		prime_addr = primary_addresses().make_primary_address(address)
		positive_balance = self.receiver_check(prime_addr, chain)
		negative_balance = -1 * self.sender_check(prime_addr, chain)
		current_bal = self.check_current(prime_addr, fake_BC=fake_BC)

		balance = positive_balance + negative_balance + current_bal
		return {'receive address': prime_addr, 'balance': balance, 'transactions': self.transactions}


	def check_current(self, primary_address:str, fake_BC:dict):
		""" Checks the balance with the unconfirmed transaction to prevent double spending """
		try:
			amount = fake_BC['amount']
		except:
			amount = None
		try:
			if primary_address == fake_BC['sender']:
				self.transactions.append({'send':fake_BC})
				return -1 * amount
			if primary_address == fake_BC['receiver']:
				self.transactions.append({'receive':fake_BC})
				return amount
		except:
			return 0










	def receiver_check(self, primary_address, blockchain):
		i = 1 
		balance = 0
		if 1 < len(blockchain):
			while i != len(blockchain):
				transactions = blockchain[i]['data']
				for transaction in transactions:
					receivers = transaction['receiver']
					
					for receiver in receivers:
						amount = transaction['amount']
						verify_wallet = self.verify_stealth_keys(receiver, primary_address)
						
						if verify_wallet == True:
							verify_double_spend = self.double_spend_check(stealth_key=receiver, chain=blockchain)
							if verify_double_spend == False:
								self.transactions.append({'receive':transaction})
								balance = balance + amount
				i = i + 1
		return balance


	def sender_check(self, sender_receive_key, blockchain):
		i = 1
		balance = 0
		if 1 < len(blockchain):
			while i != len(blockchain):
				transactions = blockchain[i]['data']
				for transaction in transactions:
					senders = transaction['sender']
					sender_signature = transaction['sender signature']
					for sender in senders:
						amount = transaction['amount']
						verify_wallet = self.verify_stealth_keys(sender, sender_receive_key)
						verify2 = self.verify_keys(sender_receive_key, sender_signature)
						if verify_wallet == True and verify2 == True:
							verify_double_spend = self.double_spend_check(stealth_key=sender, chain=blockchain)
							if verify_double_spend == False:
								self.transactions.append({'send':transaction})
								balance = balance + amount
				i = i + 1
		return balance


				
	def double_spend_check(self, stealth_key, chain):
		self.stealth_addresses = []
		double_spend = False
		if len(chain) > 1:
			for addresses in self.stealth_addresses:
				if stealth_key == addresses:
					double_spend = True
					return double_spend
				else:
					double_spend = False
			if double_spend == False:
				self.stealth_addresses.append(stealth_key)
				return double_spend
		else:
			double_spend = True
			return double_spend

	def verify_keys(self, publickey, privatekey):
		full_publickey = '$pbkdf2-sha256$29000$'+publickey
		
		try:
			verify = pbkdf2_sha256.verify(privatekey, full_publickey)

		except ValueError or TypeError or KeyError or EncodingWarning:

			verify = False
		return verify



		

	def sign_transactions(self, transaction):
		signature = Signatures()
		data = signature.gatherSendersAndReceivers(transaction)
		combined_data = signature.makeSignatures(data)
		hashdata = signature.hashSignature(combined_data)
		return hashdata


class Decoy_addresses():
	def __init__(self):
		pass
	def decoy_keys(self):
		""" makes decoy keys """
		password = Make_Keys().make_password()
		decoy_privkey = pbkdf2_sha256.hash(str(password))
		decoy_privkey= decoy_privkey.replace('$pbkdf2-sha256$29000$', '')
		decoy_pubkey = pbkdf2_sha256.hash(str(decoy_privkey))
		decoy_pubkey= decoy_pubkey.replace('$pbkdf2-sha256$29000$', '')
		decoy_key = {'publickey': decoy_pubkey, 'privatekey': decoy_privkey}
		return decoy_key

	def decoy_transactions(self, transactions):
		""" makes  decoy transactions"""
		num_decoy = random.randint(12,20)
		for x in range(num_decoy):
			amount = random.uniform(1, 10000)
			key1 = self.decoy_keys()
			key2 = self.decoy_keys()
			random_amount = random.uniform(1, amount)
			random_amount = algs.network_fee(random_amount)
		transactions.append({'sender':key1['publickey'], 'receiver':key2['publickey'],'amount':random_amount})
		transactions = self.shuffle(transactions)
		return transactions

	def shuffle(self,transactions: list):
		""" Shuffles the transactions """
		length = range(len(transactions))
		for i in length:
			j = random.randint(0, i)
			transactions[i], transactions[j] = transactions[j], transactions[i]
		return transactions






if __name__ == '__main__':
	primary_addresses()
	Check_Wallet_Balance()
	Make_Keys()
	Ring_CT()
	keys = Make_Keys().make_spend_view_receive_keys()
	stealth_keys = Make_Keys().make_stealth_keys(primary_address=keys['primary address'])
	print(keys)
	print()
	print()
	print(f'stealth address: {stealth_keys}')

