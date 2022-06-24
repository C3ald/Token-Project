import hashlib
import uuid
import sys
import os
import random

class breakup_file:
	def __init__(self, file:str):
		self.file = open(file, 'rb')
		self.file_name = file
	
	def split_file(self):
		data = []
		single_data = []
		for a in self.file.read():
			if sys.getsizeof(single_data) == 250000:
				data.append(single_data)
				single_data = []
			else:
				single_data.append(a)
		return data


	
	def get_checksum(self, read_file:list):
		hashed_parts = []
		hashed_file = hashlib.blake2b(self.file.read()).hexdigest()
		row = 1
		hashed_parts.append({'name': hashed_file})
		for line in read_file:
			hashed = hashlib.blake2b(line).hexdigest()
			data = {str(row):hashed}
			hashed_parts.append(data)
			row = row + 1

	def distribute(self, broken_file, nodes):
		picked_nodes = []
		part = 1
		for data in broken_file[1:]:
			chosen_node = random.choice(nodes)
			picked_nodes.append({str(part): data[str(part)]})
			part = part + 1





