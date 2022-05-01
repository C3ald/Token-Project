from pyclbr import Class
import random
import sys
sys.path.insert(0, "././API")
# from blockchain import Blockchain
# blockchain = Blockchain()
import socket
import requests as r


class PROOF:
	""" Makes the proof for adding new blocks, highest wins """
	def __init__(self, Blockchain:Class):
		self.blockchain = Blockchain
	

	def make_proof(self, chain):
		""" Generates a proof """
		blockchain = self.blockchain
		prev_proof = chain[-1]['proof']
		proof = blockchain.proof_of_work(previous_proof=prev_proof)
		return proof






