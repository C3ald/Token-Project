import requests as r
import random
import sys
from pyclbr import Class
from tinydb import TinyDB



class PICKNODE:
	""" Voting system for a node to be picked that will make a new block"""
	def __init__(self, Blockchain, NODES):
		blockchain = Blockchain()
		self.nodes = blockchain.read_data(DataBase=NODES)
	
	def vote_on_nodes(self):
		""" Votes for a random node """
		blockchain = self.blockchain
		alive_nodes = self.alive_nodes()
		node = random.choice(alive_nodes)
		data = {'vote': 1}
		r.post(f'http://{node}/vote', json=data)
		return node
	

	def get_num_nodes(self):
		""" Gets the current number of nodes in the network """
		self.nodes = self.blockchain.read_data(TinyDB('nodes.json'))
		return self.nodes
	
	def alive_nodes(self):
		""" Gets the number of actual nodes in the network """
		theory_nodes = self.get_num_nodes()
		num_of_actual_nodes = []
		for node in theory_nodes:
			status = r.get(node)
			if status.status_code == 200:
				num_of_actual_nodes.append(node)
		return num_of_actual_nodes