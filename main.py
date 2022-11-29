from API.app import app
import uvicorn
import sys
from Utilities.cryptography_testing import *
from Utilities.Wallets import *
from Utilities.CPUmining import *

try:
	option = sys.argv[1]
except:
	uvicorn.run(app)


if option == "wallet":
	main_test()
