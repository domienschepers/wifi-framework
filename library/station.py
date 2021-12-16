from scapy.layers.dot11 import Dot11, Dot11QoS, Ether
import abc

# Import dependencies and libraries.
from dependencies.libwifi.wifi import *
from dependencies.libwifi.crypto import encrypt_ccmp
from library.daemon import Daemon
from library.testcase import Trigger, Action

# ----------------------------------- Station -----------------------------------------

class Station(Daemon):
	"""A station is an Authenticator or Supplicant which executes a test case."""
	
	def __init__(self,options):
		self.test = None
		if "test" in options:
			self.test = options.test
			del options.test # Irrelevant for Daemon.

		super().__init__(options)
		
		# Function handler and iface when in receive modus.
		self.receive_func = None
		self.receive_eth = self.receive_mon = False
		
		# Station-generic MAC addresses and packet numbers.
		self.bss = None
		self.pn = 5
		
	def perform_actions(self, trigger):
		if self.test == None:
			return
		# Log Trigger only when it is triggered.
		if self.test.is_action_triggered(trigger):
			trigger_str = Trigger().__str__(trigger)
			log(STATUS, f"Trigger = {trigger_str}.", color="orange")
			# Generate the test case upon reaching the first trigger.
			if self.test.generated is False:
				log(STATUS, f"Generating {self.test.name} test case.", \
					color="green")
				self.test.generate(station=self)
				self.test.generated = True
		# Perform all actions for the respective trigger.
		while self.test.is_action_triggered(trigger):
			act = self.test.get_next_action()
			if act.delay:
				time.sleep(act.delay)
			if act.action == Action.Receive:
				self.receive_func = act.function
				self.receive_eth = act.eth
				self.receive_mon = act.mon
			if act.action == Action.Inject:
				assert(act.frame is not None)
				if act.encrypt:
					frame = self.encrypt(act.frame,self.tk)
				else: frame = act.frame
				if act.eth is True:
					self.inject_eth(frame)
				else: self.inject_mon(frame)
				log(STATUS, "Injected " + repr(frame))
			if act.action == Action.Function:
				assert(act.function is not None)
				_ = act.function(self) # Call function.
			if act.action == Action.Reconnect:
				self.reconnect( optimized=act.optimized )
				break # Reconnecting resets trigger.
			# Check if we have more actions, if not, close down.
			if act.action == Action.Terminate or act.terminate is True:
				if act.terminate_delay:
					time.sleep(act.terminate_delay)
				self.terminate()
	
	def handle_trigger_associated(self):
		self.perform_actions(Trigger.Associated)
		
	def handle_trigger_authenticated(self):
		if not self.tk:
			self.load_keys()
		self.perform_actions(Trigger.AfterAuth)
	
	def handle_trigger_received(self):
		self.perform_actions(Trigger.Received)
		
	def handle_trigger_connected(self):
		self.perform_actions(Trigger.Connected)
		
	def handle_trigger_disconnected(self):
		self.perform_actions(Trigger.Disconnected)
	
	def encrypt(self, frame, key):
		if len(key) == 16:
			self.pn += 1
			return encrypt_ccmp(frame, key, self.pn)
		return None
	
	def handle_eth(self, frame):
		if self.receive_eth and self.receive_func(self,frame):
			self.receive_eth = False
			self.handle_trigger_received()
	
	def handle_mon(self, frame):
		if self.receive_mon and self.receive_func(self,frame):
			self.receive_mon = False
			self.handle_trigger_received()

	def terminate(self):
		log(STATUS, "Disconnecting.", color="green")
		self.wpaspy_command("TERMINATE")
		self.terminated = True
		
# ----------------------------------- Authenticator -----------------------------------

class Authenticator(Station):
	"""Authenticator Station."""
	
	def __init__(self,options):
		options.ap = True
		super().__init__(options)
		
		# Authenticator-specific sequence numbers.
		self.sn = 10
		
		# Support one client station.
		self.clientmac = None
	
	def get_header(self, qos=True):
		"""Construct a Dot11QoS-header."""
		header = Dot11(type="Data", subtype=0, SC=(self.sn << 4) | 0)
		if qos is True:
			header[Dot11].subtype = 8
			header.add_payload(Dot11QoS())
		self.sn += 1
		header.FCfield |= 'from-DS' # From AP.
		header.addr1 = self.clientmac # Destination.
		header.addr2 = self.mac # Source.
		header.addr3 = self.mac # BSSID.
		return header
		
	def handle_wpaspy(self, msg):
		"""Override the Station/Daemon-handler."""
		log(DEBUG, "daemon: " + msg)
		if "AP-STA-ASSOCIATING" in msg:
			_, clientmac = msg.split()
			self.clientmac = clientmac
			self.handle_trigger_associated()
		if "AP-STA-CONNECTED" in msg:
			self.handle_trigger_connected()
		if "AP-STA-DISCONNECTED" in msg:
			_, clientmac = msg.split()
			if self.clientmac != clientmac:
				return
			self.clientmac = None
			self.handle_trigger_disconnected()
			
# ----------------------------------- Supplicant --------------------------------------

class Supplicant(Station):
	"""Supplicant Station."""

	def __init__(self,options):
		options.ap = False
		super().__init__(options)
		
		# Supplicant-specific sequence numbers and encryption keys.
		self.sn = 10
		self.tk = self.gtk = None
		
	def load_keys(self):
		tk = self.wpaspy_command("GET tk")
		self.tk = bytes.fromhex(tk)
		gtk = self.wpaspy_command("GET gtk")
		self.gtk = bytes.fromhex(gtk)
		log(STATUS, "Loaded pairwise and group encryption keys.")
	
	def clear_keys(self):
		self.tk = self.gtk = None
		
	def reconnect(self, optimized=None):
		log(STATUS, "Reconnecting to the AP.", color="orange")
		if optimized is not None:
			self.wpaspy_command("SET reassoc_same_bss_optim " + str(optimized))
		self.wpaspy_command("REASSOCIATE")
		#self.clear_keys()
		
	def get_header(self, qos=True):
		"""Construct a Dot11QoS-header."""
		header = Dot11(type="Data", subtype=0, SC=(self.sn << 4) | 0)
		if qos is True:
			header[Dot11].subtype = 8
			header.add_payload(Dot11QoS())
		self.sn += 1
		header.FCfield |= 'to-DS' # To AP.
		header.addr1 = self.bss # Destination.
		header.addr2 = self.mac # Source.
		header.addr3 = self.bss # BSSID.
		return header
		
	def handle_wpaspy(self, msg):
		"""Override the Station/Daemon-handler."""
		log(DEBUG, "daemon: " + msg)
		if "Associated with" in msg:
			x = re.compile("Associated with (.*)")
			self.bss = x.search(msg).group(1)
			self.handle_trigger_associated()
		if "WPA: Key negotiation completed with" in msg or \
			"WPA: EAPOL processing complete" in msg:
			self.handle_trigger_authenticated()
		if "CTRL-EVENT-CONNECTED" in msg:
			self.handle_trigger_connected()
		if "CTRL-EVENT-DISCONNECTED" in msg:
			self.handle_trigger_disconnected()
	
