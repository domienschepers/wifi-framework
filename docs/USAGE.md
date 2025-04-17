# Framework Usage

We will explain the basic idea on how to use the framework.
Remember to first [install](../setup) it.


## Before Every Usage

Before every usage the python environment has to be activated:
```
source setup/venv/bin/activate
```

Note you can leave the virtual environment by executing `deactivate`.

In case you experience issues where the python virtual environment is not used when executing commands using sudo, then as a workaround you can first open a terminal/bash instance as root, and then load the virtual environment as root.


## Simulated Wi-Fi Network Interfaces

Our framework can run on simulated interfaces by using the `mac80211_hwsim` kernel module, preventing any real-world impact or radio interference.
You can use the following script to easily create these simulated wireless interfaces:
```
./setup-hwsim.sh 4
```
This will create four simulated wireless interface (when not providing an argument it creates two).
You can also manually load the `mac80211_hwsim` module using `modprobe` or similar.


## Running and Creating Test Cases

You can write test cases that allow you to reuse Wi-Fi functionality of Linux to more easily implement attacks/tests.
For instance, the framework can connect to (protected) Wi-Fi networks for you, the framework will broadcast beacons for you, and in general any Wi-Fi functionality of Linux can be reused to more quickly implement attacks/tests.

Two types of test cases can be written:

- **Action-based test cases** that inherit from the `Test` class.
  These are typically easier and shorter to write.

- **Generic test cases** that (indirectly) inherit from the `Daemon` class.
  These take more code to write but give you full control over the client or AP.


#### Action-based Test Cases

An action-based test case defines a number of sequential actions (for example, a sequence of custom Wi-Fi frames to inject into the network) which are executed upon the activation of their respective trigger.
The next action is this sequence is executed when trigger conditions becomes true.
These triggers ensure that actions are executed only upon reaching a defined moment in the life-cycle of a connection.

For example, one can specify that a frame is injected only after successfully establishing a connection (that is, after deriving fresh session keys), or when a client initiates the authentication procedure with an access point.
Test cases can be executed automatically against any network configuration, i.e., the same test case can be executed against both a home and enterprise network.

Supported Actions are:

- ```NoAction```: No action.
- ```Reconnect```: Reconnect to the access point or client station.
- ```Inject```: Inject a plaintext or encrypted frame on the ethernet or monitor interface.
- ```Function```: Execute a user-defined function at run-time.
- ```Receive```: Receive frames from the ethernet or monitor interface.
- ```Terminate```: Terminate the test case.

Supported Triggers that specify when an action should be executed are:

- ```NoTrigger```: No trigger.
- ```AfterAuth```: When a client station authenticates to the access point.
- ```Received```: When receiving a user-defined frame.
- ```Associated```: When a client station associates to the access point.
- ```Connected```: When a client station connects to the access point.
- ```Disconnected```: When a client station disconnects from the access point.

You can look at [test case examples](EXAMPLES.md) to further learn how to write action-based test cases.


#### Generic Test Cases

If you need more flexibility, you can create a generic test case.
An example of such a test case is an [implementation of the 4-way handshake](../test-4wayhs.py) in Scapy.

These test cases are created by inheriting from the `Daemon`, `Supplicant`, or `Authenticator` class.
A simple plan to write such test cases is:

1. Take the `Supplicant` or `Authenticator` class in [station.py](../library/station.py) and put it in a file `test-*.py`.

2. Now modify the client or AP behaviour as you see fit.

See an [implementation of the 4-way handshake](../test-4wayhs.py) as a test case for more information.


#### Running a Test Case

A test case is executed using the following command:

```
usage: run.py [-h] [--config CONFIG] [--binary BINARY] [--debug DEBUG] iface name
```

Note that the name of a test case is defined in its class (its not based on the filename).


#### Benefits

The benifit of writing test cases instead of directly using Scapy is:
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


<a id="id-network-configuration"></a>
#### Specifying a Network Configuration

The framework by default runs the test cases against a WPA2 network.
To change this, the configuration files for `hostapd` and `wpa_supplicant` must be updated.
This can be done manually, or by updating the symbolic links for `hostapd.conf` and `supplicant.conf` such that they point to a different configuration, for instance using:
```
cd setup
ln -s supplicant-wpa3-personal.conf supplicant.conf
```
The setup directory contains several example configuration files, such as WPA3-Personal.

To simultaneously update the `hostapd` and `wpa_supplicant` configuration files you can use the following script:
```
cd setup
./load-config.sh wpa2-personal
```
This will assume that the configuration files `hostapd-wpa2-personal.conf` and `supplicant-wpa2-personal.conf` exist and will update the symbolic links to point to these two files.


## Access Point and Client Daemon

To easily create an access point or client, for instance to check whether your test case is working as expected, you can use the following wrapper to start an access point or client, respectively:
```
./hostap.py wlan0 --ap
./hostap.py wlan1
```

The general usage of this script is:
```
usage: hostap.py [-h] [--config CONFIG] [--binary BINARY] [--debug DEBUG] [--ap] iface
```


## Extensions

The framework is designed to be easily extended to support any user-specific needs.
For example, the _hostap_ control interface can be extended with new commands, and test cases can be extended with new functionality.

See [instructions for extending the framework](EXTENSIONS.md) for more information.


## Troubleshooting

If you experience any trouble using our framework, consider the following issues and solutions.

- Is your network manager using Wi-Fi? Try to disable it:
```
nmcli radio wifi off
```

- Is any hostap process running in the background? Try to terminate them:
```
killall hostapd wpa_supplicant
```

- Are you unable to connect with the control interface? Try to send a raw `ping` command:
```
hostapd_cli -i wlan0 raw PING
wpa_cli -i wlan1 raw PING
```

- See the [troubleshooting tips of libwifi](https://github.com/vanhoefm/libwifi/blob/master/docs/linux_tutorial.md#id-troubleshooting).

