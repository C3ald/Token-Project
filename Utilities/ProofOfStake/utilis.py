import decimal as d

class UTILS:
	""" Utilities class """
	def __init__(self):
		pass

	def drange(self, x, y, jump='0.1'):
		""" range function but with floats, make sure to put the variable in a list() class """
		while x != y:
			yield float(x)
			x += d.Decimal(jump)
		return x
		




if __name__ == "__main__":
	util = UTILS()

	num = util.drange(10, 15, '0.1')
	print(list(num))