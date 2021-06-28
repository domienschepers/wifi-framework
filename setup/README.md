# Setup

It is recommend to use our framework on a disposable/staging environment only (for example, a virtual machine).

## Installation

Depending on your system, pre-requirements to install (for example, for ```hostap```) often are the following:
```
apt-get update
apt-get install git make gcc python3-venv net-tools
apt-get install libdbus-1-dev libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libssl-dev 
```

#### Hostap

We provide a customized ```hopstap``` extending the control interface.

In order to enable the extended features of our framework, the following configuraton flags have to be selected in ```.config```:
```
CONFIG_TESTING_OPTIONS=y
CONFIG_FRAMEWORK_EXTENSIONS=y
```

Our customized version can be build using:
```
cd ../dependencies
./build.sh
```

#### Python Virtual Environment

We provide a virtual python environment to manage all dependencies for the framework.

The virtual environment can be created using the following script, which additionally installs all [requirements](requirements.txt).

```
./pysetup.sh
```

Then, before every usage, the environment has to be activated:
```
source venv/bin/activate
```

Note you can leave the virtual environment using:
```
deactivate
```

## Virtual Wi-Fi Network Interfaces

Our framework can run on simulated interfaces, preventing any real-world impact or radio interference.

Linux has a kernel module which can be used to simulate an arbitrary number of WLAN radio interfaces (```mac80211_hwsim```).

#### Script

Create any number of virtual wireless interfaces (default value is two):
```
./setup-hwsim.sh 2
```

## Configuration Files

The tool uses default configuration files for ```hostapd``` and ```wpa_supplicant```.

If you want to avoid manually adding configuration parameters, you can create a symbolic link here, to use them automatically.

A symbolic link can be created as such:

```
ln -s supplicant-wpa3-personal.conf supplicant.conf
```

We provide a variety of common network configuration files, such as WPA3-Personal.

#### Script

A network configuration can be loaded quickly using our script, for example:
```
./load-config.sh wpa2-personal
```

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

- Are you unable to connect with the control interface? Try to send a raw ```ping``` command:
```
hostapd_cli -i wlan0 raw PING
wpa_cli -i wlan1 raw PING
```
