import requests as r
import time as t
import threading as th
import sys
sys.path.insert(0,"././Utilities")
from cryptography_testing import *



class Pool_miners:
	""" The class for the proof of stake pool """
	def __init__(self):
		self.pool = []
		self.wallet_check = Check_Wallet_Balance()

	def add_miner_to_pool(self, miner, stake, blockchain):
		""" Adds a miner to the proof of stake pool """
		chain = blockchain.chain
		is_valid = self.is_miner_valid(receiver_address=miner,blockchain=chain,stake=stake)
		if is_valid == True:
			data = {"miner":miner, "stake":stake, 'time': t.time()}
			self.pool.append(data)
			return "Miner has been added"
		else:
			return None
	

	def is_miner_in_pool(self,miner):
		if miner in self.pool:
			return True
		else:
			return False


	def is_miner_valid(self, receiver_address, blockchain,stake):
		""" Checks if the miner has enough stake to put in  and if the miner is valid """
		miner = receiver_address
		chain = blockchain.chain
		balance = self.wallet_check.stake_check(miner, chain)
		if balance > stake:
			return True
		else:
			return False


