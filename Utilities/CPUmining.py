import time as t
import hashlib


class Calibrate:
	""" Calibration class for CPU mining """
	def __init__(self):
		pass

	def calibrate(self):
		""" Calibrates the cpu power """
		time_started = t.time()
		for x in range(10000000):
			hashlib.sha512('hash'.encode())
			hashlib.blake2b('hash'.encode())
		time_finished = t.time()
		time_passed = time_finished - time_started
		# hashes = 100000000 / time_passed
		return time_passed
	
	def run(self):
		""" Runs the calibration """
		cali = []
		for x in range(5):
			cal = self.calibrate()
			cali.append(cal)
		total = 0
		for x in cali:
			total = total + x
		average = total / len(cali)
		print('calibration done!')
		print(average)
		return average



class Minging:
	""" CPU mining algorithm """
	def __init__(self):
		calibrate = Calibrate()
		self.hashes_a_second = calibrate.run()
	
	def calculate_difficulty(self):
		""" Calculates block difficulty """
		if self.hashes_a_second < 1:
			return '000000000000000000'
		if self.hashes_a_second > 1 and self.hashes_a_second < 4:
			return '000000000000000'
		if self.hashes_a_second > 4:
			return '00000000000'

	def run(self, previous_proof):
		difficulty = self.calculate_difficulty()
		start = t.time()
		proof = 1
		while True:
			hashd = hashlib.sha256(str(proof**2 -previous_proof**2).encode()).hexdigest()
			if hashd[:len(difficulty)] == difficulty:
				end_time = t.time()
				passed = end_time - start
				print(passed)
				return proof
			else:
				proof = proof + 1




# def random_question()




if __name__ == '__main__':
	mining = Minging()
	print(len('000000000000000000'))
	print(mining.run(10))