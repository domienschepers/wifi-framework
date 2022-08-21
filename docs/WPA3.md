# WPA3-Related Test Cases

<sup>See the [Framework README](https://github.com/domienschepers/wifi-framework) for general information about the framework.</sup>

All combined, these test cases (will) form a WPA3 exploitation framework. There
are two main targets: denial-of-service attacks despite using Management Frame
Protection (MFP) and network-based attacks against SAE Public Key (SAE-PK).

First load the WPA3-MFP config using:

	./load-config.sh wpa3-personal-pmf

And then you can perform the tests below against WPA3.

These following attacks are further discussed in the talk ["Attacking WPA3: New Vulnerabilities and Exploit Framework"](https://conference.hitb.org/hitbsecconf2022sin/session/attacking-wpa3-new-vulnerabilities-and-exploit-framework/).


## Denial-of-Service

With WPA3 the usage of Management Frame Protection (MFP) is mandatory. Among
other things, this prevents denial-of-service attacks such as the infamous
deauthentication attack. However, implementations may still be vulnerable to
other denial-of-service attacks. You can test the following tests to check
whether an AP or client is vulnerable to denial-of-service attacks even when
MFP is being used:

- `example-pmf-deauth`: tests whether an AP is vulnerable to `CVE-2019-16275`.
  If the AP is vulnerable, this can be abused to disconnect all clients.

- `dos-beacon-csa`: tests whether unprotected beacons with a Channel Switch
  Announcement (CSA) causes the client to disconnect.

- `dos-beacon-bandwidth`: tests whether spoofing a beacon that specifices a
  primary channel of 1 with the secondary channel below it will cause the
  client to disconnect (because this bandwidth configutation is invalid).

- `dos-sae-flood`: injects a flood of SAE messages towards the WPA3 AP. Against
  the DIR-X1860 it takes roughly 400 messages to crash it. Modify the config
  in `setup/supplicant.conf` to specify the name of the network to test.


## SAE-Public Key

In the version 3 update to the WPA3 specification, the new SAE Public Key
protocol was added. This protocol allows the creation of a hotspot where
users authenticated using a pre-shared password, but an adversary cannot
use the pre-shared password to clone the network. When setting up an SAE-PK
network it's important to disable client-to-client traffic, otherwise
network-based attacks are still possible. Additionally, an adversary can try
to abuse the group key to inject unicast IP packets. To test whether a client
accepts unicast IP packets inside a broadcast Wi-Fi frame, you can use the
following tests:

- `group-hole196`: tests whether a client accepts unicast IP packets inside
  encrypted broadcast frames. An adversary may be able to abuse this to inject
  traffic towards a client inside an SAE-PK network even though the AP blocks
  client-to-client communication.

- `group-tods`: tests whether the AP accepts encrypts broadcast frames that
  contain an ICMP ping request towards a client in the network. This allows
  a client to abuse the group key to inject unicast IP packets even when
  clients are not affected by the `group-hole196` test.

