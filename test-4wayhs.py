# Import dependencies and libraries.
from dependencies.libwifi.wifi import *
from dependencies.libwifi.crypto import rsn_prf_sha1, aes_wrap_key_withpad
from library.station import Authenticator

from scapy.contrib.wpa_eapol import WPA_key
from pbkdf2 import PBKDF2

class FourWayHandshake(Authenticator):
	"""Authenticator Station."""
	name = "handshake-ap"

	def send_msg1(self):
		self.anonce = random.randbytes(32)
		self.replay_counter += 1

		p = WPA_key(descriptor_type=2,
					key_info=0x008a,
					replay_counter=struct.pack(">Q", self.replay_counter),
					nonce=self.anonce)
		p = LLC()/SNAP()/EAPOL(version="802.1X-2004", type="EAPOL-Key")/p
		p = self.get_header()/p

		log(STATUS, f"Sending msg1: {repr(p)}")
		self.sock_mon.send(p)


	def process_msg2(self, p):
		self.snonce = p[WPA_key].nonce
		log(STATUS, f"Received snonce {self.snonce}")

		self.derive_ptk()

		eapol = p[EAPOL].copy()
		eapol.wpa_key_mic = b"\x00" * 20
		mic = hmac.new(self.ptk[0:16], bytes(eapol), hashlib.sha1).digest()[0:16]
		log(STATUS, f"Calculated MIC: {mic}")
		log(STATUS, f"Received MIC:   {p[EAPOL].wpa_key_mic}")


	def send_msg3(self):
		self.replay_counter += 1

		# Get the RSNE from hostap
		rsne = binascii.unhexlify(self.wpaspy_command("GET_RSNE"))

		# Get GTK from Hostapd so it's of the correct length in all cases
		gtk, gtk_index = self.wpaspy_command("GET_GTK").split()
		gtk = binascii.unhexlify(gtk)
		gtk_index = int(gtk_index)

		# See Figure 12-36—GTK KDE format:
		# - The first byte is: Key ID (2 bits), Tx (1 bit), Reserved (3 bits)
		# - The second byte is Reserved (8 bits)
		gtk_info  = struct.pack(">B", gtk_index) + b"\x00"
		key_data  = bytes(Dot11EltVendorSpecific(oui=0x000fac, info=b"\x01" + gtk_info + gtk))
		key_data += rsne

		# Encrypt the key data
		kekkey = self.ptk[16:32]
		log(STATUS, f"KEK Key:   {kekkey}")
		log(STATUS, f"Plaintext: {key_data}")
		ciphertext = aes_wrap_key_withpad(kekkey, key_data)
		log(STATUS, f"ciphertext: {ciphertext}")

		eapol = WPA_key(descriptor_type=2,
					key_info=0x13CA,
					len=len(gtk),
					replay_counter=struct.pack(">Q", self.replay_counter),
					nonce=self.anonce,
					wpa_key_length=len(ciphertext),
					wpa_key=ciphertext)
		eapol = EAPOL(version="802.1X-2004", type="EAPOL-Key")/eapol
		eapol.wpa_key_mic = hmac.new(self.ptk[0:16], bytes(eapol), hashlib.sha1).digest()[0:16]

		p = LLC()/SNAP()/eapol
		p = self.get_header()/p

		log(STATUS, f"Sending frame {repr(p)}")
		self.sock_mon.send(p)


	def derive_ptk(self):
		# TODO: Get the SSID and passphrase through the hostap control interface
		ssid = "testnetwork"
		passphrase = "passphrase"
		pmk = PBKDF2(passphrase, ssid, 4096).read(32)

		apmac = binascii.a2b_hex(self.mac.replace(":", ""))
		stamac = binascii.a2b_hex(self.clientmac.replace(":", ""))
		apnonce = self.anonce
		stanonce = self.snonce
		label = b"Pairwise key expansion"
		key_data = min(apmac,stamac) + max(apmac,stamac) + min(apnonce,stanonce) + max(apnonce,stanonce)

		self.ptk = rsn_prf_sha1(pmk, label, key_data, 512//8)
		log(DEBUG, f"PTK: {self.ptk}")


	def start_handshake(self, msg):
		self.clientmac = msg.split()[1]
		self.replay_counter = 0
		log(STATUS, f"Starting handshake with {self.clientmac}")

		self.send_msg1()


	def handle_started(self):
		# After hostap started, configure to skip the 4-way handshake
		# so we can handle it ourselves
		self.wpaspy_command("SKIP_4WAY 1")


	def handle_mon(self, p):
		if p.addr2 != self.clientmac or p.addr1 != self.mac:
			return

		if EAPOL in p:
			self.handle_eapol(p)
							
	def handle_eapol(self, p):
		log(STATUS, f"Received {repr(p)} length={len(p)}")

		# Message 4 can be detected because the key data field is empty:
		if WPA_key in p and p[WPA_key].wpa_key_length == 0:
			log(STATUS, "Received message 4, handshake complete!")
			
		# Otherwise assume it's message 2
		else:
			self.process_msg2(p)
			self.send_msg3()

	def handle_wpaspy(self, msg):
		"""Override the Station/Daemon-handler."""
		log(STATUS, "daemon: " + msg)
		if "AP-STA-ASSOCIATING" in msg:
			self.start_handshake(msg)

