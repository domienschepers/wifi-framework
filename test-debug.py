# Import dependencies and libraries.
from dependencies.libwifi.wifi import *
from library.testcase import Trigger, Action, Test

# ----------------------------------- Debug Functionality -----------------------------

class DebugAuthenticator(Test):
	name = "debug-ap"
	kind = Test.Authenticator
	
	def __init__(self):
		super().__init__([])
		
	def generate(self, station):
		pass

class DebugSupplicant(Test):
	name = "debug-client"
	kind = Test.Supplicant
	
	def __init__(self):
		super().__init__([])
		
	def generate(self, station):
		pass
		
