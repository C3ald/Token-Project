from API.app import app
import uvicorn
<<<<<<< HEAD


uvicorn.run(app)
=======
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
>>>>>>> 93447e50baea94115edeecf17a37cd2ae249d457
