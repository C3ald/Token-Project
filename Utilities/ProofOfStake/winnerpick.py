import random
from utilis import UTILS
import time
utils = UTILS()


miners = [{'miner':'joe', 'stake':20},{'miner':'bob',"stake":60}, {"miner":"jim","stake":30}, {"miner":"nancy","stake":50}]

class PickWinner:
	def __init__(self):
		self.winner = None
		self.pool_of_stakers = []
	
	def pick_winner(self, miners:list):
		miners = miners
		for miner in miners:
			deci = list(utils.drange(0,miner['stake']))
			for item in deci:
				self.pool_of_stakers.append(miner['miner'])
		winner = random.choice(self.pool_of_stakers)
		return winner


	def time_check(self, previous_block):
		""" If it has been at least 5 minutes the new block will be accepted """
		t = time.time()
		time_of_previous_block = previous_block['timestamp']
		difference = t - time_of_previous_block
		if difference > 100.0:
			return True
		return False
		


	def format_time(self, time_now, time_previous_block):
		""" Formats the time """
		if time_now in time_previous_block:
			time_now.replace(time_previous_block, '')
		return time_now

	
	def start_proof_of_stake(self, chain):
		""" Starts the winner sequence """
		time_to_add = self.time_check(chain[-1])
		if time_to_add == True:
			winner = self.pick_winner()
			return winner
			




if __name__ == "__main__":
	winner_picker = PickWinner()
	winn = []
	stakers = []
	for x in range(100):
		winner = winner_picker.pick_winner(miners)
		winn.append(winner)

	for item in miners:
		stakers.append(item['miner'])


	for i in stakers:
		print(f'miner: {i} won: {winn.count(i)}%')
	# print(winner)
