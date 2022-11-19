from tinydb import TinyDB
import sys
import time
sys.path.insert(0, "././API")
from pyclbr import Class
# from blockchain import Blockchain
STAKERS = TinyDB('stakers.json')
# blockchain = Blockchain()

class stake_pool:
	""" Handles the database of miners staking """
	def __init__(self, Blockchain:Class):
		blockchain = Blockchain
		self.blockchain = blockchain
		self.list_of_stakers = []

	
	def update_data_base_for_stake_pool(self, staker:str, stake:float):
		""" Updates the staker database """
		data = {"staker": staker, "stake": stake, 'time':time.time()}
		self.list_of_stakers.append(data)
		self.blockchain.add_data(STAKERS, data=self.list_of_stakers)
	
	def list_stakers(self):
		""" List the stakers """
		data = self.list_of_stakers
		data = self.blockchain.read_data(STAKERS)
		return data
	
	def remove_staker(self, staker:str):
		""" Removes a staker from the staking pool """
		data = self.list_stakers()
		for item in data:
			if item['staker'] == staker:
				data.remove(item)