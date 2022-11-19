from pyclbr import Class
import sys

# API = sys.path.insert(0,"../../API")
# print(API)
# from blockchain import Blockchain

import requests as r

 

class Stake_Punishment:
	def __init__(self, Blockchain:Class):
		self.blockchain = Blockchain()
		self.chain = self.blockchain.chain
	
	def take_stake_away(self, miner_and_stake:dict):
		""" Takes the stake away if something like tampering with blocks happens """
		miner = miner_and_stake['miner']
		stake = miner_and_stake['stake']
		self.blockchain.add_miner_transaction(sender=self.miner, receiver="Network", amount=self.stake)
		return "Stake has been taken away!"
	

