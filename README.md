# Wi-Fi Framework

We present a framework to test and fuzz Wi-Fi devices (access points and client stations).

The framework is implemented on top of the _hostap_ user space daemon, and encompasses a language to define complex test cases which can be executed automatically against any device, supporting any network configuration.

<p align="center">
	<img width="500" src="dependencies/repository/framework.png">
	<br />
	<em>Overview of the Wi-Fi Daemon and Framework components.</em>
</p>

#### Benefits

Our framework offers a number of notable benefits, for example:
- Powerful yet simple language to define test cases.
- Support for both access points and client stations.
- Support for the _hostap_ control interface, allowing the reuse of existing built-in functionality.
- Support for any authentication algorithm, allowing the evaluation of any (enterprise) network configuration.
- Support for customized _hostap_ binaries and network configuration files.
- Support for virtualized wlan radios using ```mac80211_hwsim```.

Furthermore, usage of a user space daemon ensures the framework: 
- Automatically transmits beacon frames announcing the network when operating an access point.
- Automatically transmits acknowledgments to incoming frames (by the hardware without delay).
- Automatically retransmits frames when no acknowledgment is received.
- Automatically buffers injected frames for a client when it is in sleep mode.

#### Use Cases

Common uses cases of the framework include testing hypothesis on new weaknesses, implementing proof-of-concepts, building fuzz-testing tools, creating testing suits (for example, evaluate if a device is vulnerable to known attacks), and automating experiments.

Example:
- [FragAttacks: Fragmentation & Aggregation Attacks](https://github.com/vanhoefm/fragattacks)

## Test Cases

A test case defines a number of sequential actions (for example, a sequence of user-modified frames to inject into the network) which are executed upon the activation of their respective trigger.
Triggers ensure actions are executed only upon reaching a defined moment in the life-cycle of a connection.
As such, we are able to define actions which meet certain requirements.
For example, one may require a frame is injected only after successfully establishing a connection (that is, after deriving fresh session keys), or when a client initiates the authentication procedure with an access point.
Test cases can be executed automatically against any device, supporting any network configuration (for example, enterprise networks).
 
#### Supported Actions

- ```NoAction```: No action.
- ```Reconnect```: Reconnect to the access point or client station.
- ```Inject```: Inject a plaintext or encrypted frame on the ethernet or monitor interface.
- ```Function```: Execute a user-defined function at run-time.
- ```Receive```: Receive frames from the ethernet or monitor interface.
- ```Terminate```: Terminate the test case.

#### Supported Triggers

- ```NoTrigger```: No trigger.
- ```AfterAuth```: When a client station authenticates to the access point.
- ```Received```: When receiving a user-defined frame.
- ```Associated```: When a client station associates to the access point.
- ```Connected```: When a client station connects to the access point.
- ```Disconnected```: When a client station disconnects from the access point.

## Extensions

<sup>See [instructions for extending the framework.](EXTENSIONS.md)

The framework is designed to be easily extended to support any user-specific needs.
For example, the _hostap_ control interface can be extended with new commands, and test cases can be extended with new functionality.

## Code

<sup>See [installation and configuration instructions.](setup)

We provide the tools to swiftly evaluate any test case.
All daemons support customized configuration files and _hostap_ binaries, enabling one to quickly switch between various software and network configurations.

#### Python Virtual Environment

Activate the Python3 virtual environment before every usage:
```
source setup/venv/bin/activate
```

#### Access Point and Client Daemon

We provide a wrapper for spawning an Acccess Point or Client daemon:

```
usage: hostap.py [-h] [--config CONFIG] [--binary BINARY] [--debug DEBUG] [--ap] iface
```

Examples:
```
./hostap.py wlan0 --ap
./hostap.py wlan1
```

#### Running a Test Case

A test case is executed using the following command:

```
usage: run.py [-h] [--config CONFIG] [--binary BINARY] [--debug DEBUG] iface name
```

Example:
```
./run.py wlan0 example-demo
```

New test cases can be written in any file using template ```test-*.py``` and require no further framework changes.

## Example

<sup>See [a detailed description of all our examples.](EXAMPLES.md)

In the following example, we demonstrate how a test case is written, and highlight basic features.

#### Definition
```python
class Demonstration(Test):
	""" Simplified demonstration presenting the basic test case structure.
	"""
	name = "example-demo"
	kind = Test.Supplicant
	
	def __init__(self):
		""" Initialization of the sequential actions defining the test case.
		"""
		super().__init__([
			# Once authenticated, we will inject a frame.
			Action( trigger=Trigger.AfterAuth, action=Action.Inject ),
			# Once connected, we will call a user-defined function. 
			Action( trigger=Trigger.Connected, action=Action.Function )
		])
	
	def ping(self, station):
		""" User-defined function, giving us run-time access to the station.
		""" 
		# For example, we will send a command over the control interface. 
		response = station.wpaspy_command("PING")
		if "PONG" in response:
			log(STATUS,'Received a PONG from the control interface.')
		
	def generate(self, station):
		""" Generate the test case by configuring the defined actions. 
		"""
		
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

#### (Optional) Interfaces

Simulate two wireless network interfaces (Wi-Fi radios):
```
./setup/setup-hwsim.sh 2
```

#### (Optional) Configuration

Load configuration ```wpa2-personal```:
```
cd setup; ./load-config.sh wpa2-personal
```

#### Execution

Spawn an access point daemon:
```
./hostap.py wlan0 --ap
```

Run the demonstration:
```
./run.py wlan1 example-demo
```

## Publication

This work was published at ACM Conference on Security and Privacy in Wireless and Mobile Networks (WiSec '21):

- [DEMO: A Framework to Test and Fuzz Wi-Fi Devices](https://dl.acm.org/doi/10.1145/3448300.3468261)
