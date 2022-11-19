from pyclbr import Class
import requests as r
# from picknode import PICKNODE

# picknode = PICKNODE()

class VOTING:
	def __init__(self, Blockchain:Class):
		blockchain = Blockchain()
		self.nodes = blockchain.nodes
		self.num_of_nodes = len(self.nodes)
	
	def count_votes(self, picknode:Class):
		""" Counts the votes """
		alive_nodes = picknode.alive_nodes()
		num_of_votes = 0
		voted_nodes = []
		for node in alive_nodes:
			request = r.get(f'{node}/votes')
			request_json = request.json()
			data = request_json['votes']
			data_json = {'node': node, 'votes': data}
			voted_nodes.append(data_json)
			num_of_votes = num_of_votes + data
		
		if num_of_votes <= self.num_of_nodes:
			return True
		return False
	
	def pick_most_popular(self, voted_nodes):
		""" Picks the winner """
		votes = []
		for item in voted_nodes:
			votes.append(item['votes'])
		most_popular = max(votes)
		for item in voted_nodes:
			if item['votes'] == most_popular:
				return item
	
	def get_voted_nodes(self, picknode:Class):
		""" Gets the voted nodes """
		alive_nodes = picknode.alive_nodes()
		return alive_nodes

				

		


