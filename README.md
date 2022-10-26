# jNetPcap version 2
jNetPcap is a *libpcap* java binding. This is version 2 release of popular **jNetPcap** library, previously hosted on SourceForge.net.

### Compatibility with jNetPcap version 1
[Version 1  of **jNetPcap**][jnetpcap_v1_page] was released some 10 years ago. Version 2 has numerous backward incompatiblities with version 1, but overall version 1 based application can be easily upgraded to version 2.

The license changed from LGPL to a less ristrictive Apache v2 license.

Lastly, version 1  of **jNetPcap**, had a lot of functionality bundled in that did not belong at the *libpcap* binding level. In version 2 all extraneous functinality has been factored out into separate modules. This allows greater flexibility and less impact on the main **jNetPcap** module stability.

## Overview
**jNetPcap** provides out of the box *libpcap* library bindings from *Java JRE*. By using *Foreign Function* features of *Java JRE*, **jNetPcap** can bind directly to all the native *libpcap* library functions and provides full functionality of underlying native *libpcap* library. All native *libpcap* functions, including legalcy *WinPcap* and latest *Npcap* libraries as well, on *Microsoft Windows* platforms. 

## Examples
Capturing packets is straight forward and easy out of the box:

### Live Packet Capture
This quick example demonstrates how to capture 1 or more packets from a live network.
```java
void main() throws PcapException {
	int PACKET_COUNT = 1;
	List<PcapIf> devices = Pcap.findAllDevs();

	try (Pcap pcap = Pcap.create(devices.get(0))) {
		pcap.activate();

		pcap.loop(PACKET_COUNT, (String msg, PcapHeader header, byte[] packet) -> {

			System.out.println(msg);
			System.out.printf("Packet [timestamp=%s, wirelen=%-4d caplen=%-4d %s]%n",
					Instant.ofEpochMilli(header.toEpochMillis()),
					header.wireLength(),
					header.captureLength(),
					PcapUtils.toHexCurleyString(packet, 0, 6));

		}, "Hello World");
	}
}
```

Which produces the following output:

```
Hello World
Packet [timestamp=2011-03-01T20:45:13.266Z, wirelen=74   caplen=74   {00:26:62:2f:47:87}]
```
### Transmit a Packet
This example demonstrates how to transmit a raw packet on a live network:
```java
void main() throws PcapException {

	/* raw bytes of our packet */
	final String ETHERNET = "0026622f4787001d60b301840800";
	final String IPv4 = "4500003ccb5b4000400628e4 c0a8FD05 c0a8FD06";
	final String TCP = "e14e00508e50190100000000a00216d08f470000020405b40402080a0021d25a0000000001030307";
	final byte[] packetBytes = PcapUtils.parseHexString(ETHERNET + IPv4 + TCP);

	List<PcapIf> devices = Pcap.findAllDevs();

	try (Pcap pcap = Pcap.create(devices.get(0))) {
		pcap.activate();

		/* Transmit our packet */
		pcap.sendPacket(packetBytes);
	}
}
```
Note that **Pcap.inject** can also be used to transmit packets. This example produces no output, but if you monitor the network, you will see our non-routable packet being sent from the example host.

### For more examples
See the [wiki] pages. Project's [unit tests][unit_test] are also a great source for usage examples of every single function in the module.

## Dependencies
**jNetPcap** binding has been designed to be extremely light and not have very few depdencies.

### Java Dependencies for Module: org.jnetpcap
* No java dependencies except for standard java modules and the *Foreign Function* feature, currently in java *preview*, but one which is expected to be a permanent feature, in the near future.

### Native libbrary depdencies
* The only native dependency is the native *libpcap* library itself, which has to be installed prior to **jNetPcap** module initializing. All versions of *libpcap* API are supported, from *libpcap* version 0.4 to the current latest version 1.5. This also includes the latest *WinPcap* and *Npcap* derivatives on *Microsfot Windows* platforms.

## Installation
There are several methods for installing the the software

### Maven installation
```
<dependency>
    <groupId>org.jnetpcap</groupId>
    <artifactId>jnetpcap</artifactId>
    <version>2.0.0-alpha.1</version>
</dependency>

```
### Download Release Package
* TODO: add link to release

### Compile From Source
You will find instructions how to compile from source on our [Wiki Pages][wiki].

## Related Modules
Previously embeded functionality into **jNetPcap** version 1, has be refactored into a separate modules. 
### Module: org.jnetpcap.packet
Provides high level packet dissecting and decoding functionality. It requires 'org.jnetpcap' module, and has several other depdencies (listed in the 'jnetpcap-packet' repo.)
**Todo:** add link to jnetpcap-packet module

## Usage
See [Wiki pages][wiki]


[jnetpcap_v1_page]: <https://sourceforge.net/projects/jnetpcap> "Legacy jNetPcap Version 1 Project Page"
[wiki]: <https://github.com/slytechs-repos/jnetpcap/wiki> "jNetPcap Project Wiki Pages"
[unit_test]: <https://github.com/slytechs-repos/jnetpcap/blob/main/src/test/java/org/jnetpcap/test/LibpcapApiTest.java> "jUnit Test of Main Libpcap API bindings"

