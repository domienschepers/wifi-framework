# Extensions

Extensions can be made to the framework to support any user-specific requirement.

We discuss how to extend the _hostap_ control interface, used by both `hostapd` and `wpa_supplicant`, as well as how to extend the framework's test case functionality.

## Extending the Control Interface

In _hostap_, Access Points and Clients have a dedicated control interface. Other programs can send
commands to _hostap_ over this control interface, which is implemented using UNIX domain sockets.
The control interface will also send events (status messages) over this control interface (e.g. when
a client connected to the access point). This control interface is implemented in the following files: 
```
/dependencies/hostap_2_9/hostapd/ctrl_iface.c
/dependencies/hostap_2_9/wpa_supplicant/ctrl_iface.c
```
Making adjustments to the respective `ctrl_iface.c` file will allow us to add new functionality to an access point or client station.


#### Command Prefix

When using the control interface, we need to differentiate between command responses and events (status messages)
that hostap may send at any time. To accomplish this, we prepend all control interface commands and responses with
a `> ` prefix. This allows the framework to properly identify responses to commands (and not accidently interpret
an event as a command response).

#### Example

As an example, we add a `GET_BSSID` command to the suppliciant which returns the network's BSSID.

First, we must edit the function `wpa_supplicant_ctrl_iface_process` in `hostap_2_9/wpa_supplicant/ctrl_iface.c`:
```c
#ifdef CONFIG_FRAMEWORK_EXTENSIONS
	} else if (os_strcmp(buf, "GET_BSSID") == 0) {
		reply_len = wpa_supplicant_ctrl_iface_get_bssid(
			wpa_s, reply, reply_size);
#endif /* CONFIG_FRAMEWORK_EXTENSIONS */
```
Our new command now calls a non-existing function named ```wpa_supplicant_ctrl_iface_get_bssid```, implementing the command.

Second, we write a definition for the new functionality:
```c
#ifdef CONFIG_FRAMEWORK_EXTENSIONS
static int wpa_supplicant_ctrl_iface_get_bssid(
	struct wpa_supplicant *wpa_s, char *buf, size_t buflen)
{
	return os_snprintf(buf, buflen, MACSTR, MAC2STR(wpa_s->bssid));
}
#endif /* CONFIG_FRAMEWORK_EXTENSIONS */
```

Since we can pass the ```struct wpa_supplicant``` reference, our function is able to access all station-specific information.

As such, endless new features can be added to a new control interface command.

#### Development

Notice in the above example that the added code is put between "ifdef guards".
It's recommended to follow this practice so that it's easy to differentiate between code that's part of the official hostap version and our custom extensions.

While compiling the framework the `.config` files will automatically enable these defines by including the following two lines in the cofig:
```
CONFIG_TESTING_OPTIONS=y
CONFIG_FRAMEWORK_EXTENSIONS=y
```

#### Example Test Case

See [an example test case issuing the new control interface command.](EXAMPLES.md#customized-control-interface-command)

## Extending the Test Case Functionality

The functionality of a test case can be extended, in order to support new features.

For example, one can add new triggers, or offload common functionality to the station classes.

Stations and test cases are implemented in the following files:
```
/library/station.py
/library/testcase.py
```

#### Example

As an example, we added Supplicant functionality to create a Dot11QoS-header:

```python
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
```

The Dot11QoS-header is constructed using information directly known to the Supplicant (for example, its own MAC address).

In a test case, we can then write the following:

```python
# Create a Dot11QoS-frame with dummy payload.
frame = station.get_header() # Returns Dot11QoS()-header.
frame /= LLC()/SNAP()/Raw(b'A'*32)

# Load the frame into our action, and let us sent it encrypted.
self.actions[0].set_frame( frame , mon=True , encrypt=True )
```

Such functionality eases the definitions of test cases, as the implementation of this functionality can be added to the station class.

