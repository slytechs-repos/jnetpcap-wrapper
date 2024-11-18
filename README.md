![Maven Central](https://img.shields.io/maven-central/v/com.slytechs.jnet.jnetpcap/jnetpcap-wrapper?link=https%3A%2F%2Fmvnrepository.com%2Fartifact%2Fcom.slytechs.jnet.jnetpcap%2Fjnetpcap-wrapper)
![Sonatype Nexus (Snapshots)](https://img.shields.io/nexus/s/com.slytechs.jnet.jnetpcap/jnetpcap-wrapper?server=https%3A%2F%2Fs01.oss.sonatype.org%2F)

# jNetPcap Wrapper
Unlock Network Packet Analysis in Java with **jNetPcap Wrapper**

**jNetPcap Wrapper** is a [*libpcap*][libpcap] java library. This is **version 2** release of the popular **jNetPcap** library, previously hosted on [*SourceForge.net*][sf.net].

## Overview
Harness the power of libpcap within your Java applications using jNetPcap Wrapper, a bridge that grants you seamless access to low-level network monitoring capabilities.

Key Features:

* Capture and Analyze Network Traffic: Intercept packets in real-time, delving into their contents for in-depth analysis and insights.
* Streamlined Integration: Effortlessly incorporate the library into your projects using dependency managers like Maven or by manually adding it to your classpath.
* Intuitive Java API: Interact with network data through a familiar Java interface, eliminating the need for complex native code.
* Packet Capture and Handling: Employ the Pcap class to initiate packet capture on a chosen network interface, and utilize PcapPacketHandler to process captured packets efficiently.
* Precise Packet Filtering: Implement granular filters to isolate specific packets based on criteria such as port numbers, protocols, or IP addresses, refining your analysis.
* 
Key Steps to Get Started:

* Installation: Add jNetPcap Wrapper as a dependency in your Maven project's pom.xml file or download and manually integrate it into your classpath.
* Interface Selection: Instantiate a Pcap object, representing the network interface you intend to monitor.
* Packet Handling: Create a PcapPacketHandler instance to process captured packets as they arrive.
* Filtering (Optional): Craft filters to narrow down captured packets based on specific constraints using the library's filtering capabilities.

Unlock a Realm of Network Analysis Possibilities:

* Construct custom network monitoring tools.
* Develop sophisticated packet analyzers.
* Implement intrusion detection systems.
* Design network forensic tools.
* Conduct comprehensive network troubleshooting and optimization.

## See Also
If you are looking for protocol enabled version of this library, please see the full [**jNetPcap SDK**][jnetpcap-sdk] or for advanced functionality the [**jNetWorks SDK**][jnetworks-sdk] library.

##  API Diagram
This diagram illustrates the architecture of jnetpcap-wrapper and how it interacts with various components of the system.

```mermaid
graph TD
    A[Java Application] --> B[jnetpcap-wrapper]
    B --> C[Panama/JEP-424 Foreign Function & Memory API]
    C --> D[Libpcap / WinPcap / Npcap]
    D --> E[Operating System]
    E --> F[Network Drivers]
    F --> G[Network Interface Cards]

    subgraph "User Space"
        A
        B
    end

    subgraph "Foreign Function Interface"
        C
    end

    subgraph "Native Library"
        D
    end

    subgraph "Kernel Space"
        E
        F
    end

    subgraph "Hardware"
        G
    end

    classDef userSpace fill:#e6f3ff,stroke:#0066cc,stroke-width:2px,color:#000000
    classDef ffi fill:#fff2e6,stroke:#ff9933,stroke-width:2px,color:#000000
    classDef nativeLib fill:#e6ffe6,stroke:#00cc66,stroke-width:2px,color:#000000
    classDef kernelSpace fill:#ffe6e6,stroke:#cc0000,stroke-width:2px,color:#000000
    classDef hardware fill:#f2e6ff,stroke:#6600cc,stroke-width:2px,color:#000000

    class A,B userSpace
    class C ffi
    class D nativeLib
    class E,F kernelSpace
    class G hardware
```
*	User Space: Where the Java application and jnetpcap-wrapper operate.
*	Foreign Function Interface: The interface between Java and native code.
*	Native Library: Where libpcap/WinPcap operates.
*	Kernel Space: The operating system and driver level.
*	Hardware: The physical network interface cards.

## Documentation

See [*Wiki pages*][wiki] for user guides and examples.

See [*Javadocs*][javadocs] reference documentation.

## Where are the protocols found in v1?
If you are looking for protocol support, same as it was available in v1, this functionality has been moved to other modules. In this way, **jNetPcap Wrapper** module's functionality is focused on providing accurate modeling of native *libpcap* APIs in java. 

For protocols and familiar v1 APIs such as
```
Packet pack = ...;
Ip4 ip4 = new Ip4();
if (packet.hasHeader(ip4))
  System.out.printf("IPv4.version=%d%n", ip4.version());
```
please use [**jnetpcap-sdk**][jnetpcap-sdk] module which extends that basic **jNetPcap Wrapper** API (ie. `NetPcap extends Pcap`) by providing additional protocol level features and API.

> **Note:** The protocol definitions are in their own modules called **protocol packs** found in [**protocol-pack-sdk**][protocol-pack-sdk] repository and maven artifacts.

## Examples
To get started lets take a look at a couple of examples.

Capturing and transmitting packets is straight forward and easy out of the box. 

> **Note**! **jNetPcap** also provides many useful utilities to help in working with the data received, such as byte arrays to hex string, and hex string to byte array, and much more. More advanced utility packet handlers such as no-copy on capture, are provides as well and discussed in the [*Wiki pages*][wiki]. 

### Capture a Live Packet
This quick example demonstrates how to **capture one or more packets** from a live network.
```java
void main() throws PcapException {
	int PACKET_COUNT = 1;
	List<PcapIf> devices = Pcap.findAllDevs();

	try (Pcap pcap = Pcap.create(devices.get(0))) {
		pcap.activate();

		pcap.loop(PACKET_COUNT, (String msg, PcapHeader header, byte[] packet) -> {

			System.out.println(msg);
			System.out.printf("Packet [timestamp=%s, wirelen=%-4d caplen=%-4d %s]%n",
					Instant.ofEpochMilli(header.toEpochMilli()),
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
### Transmit a Packet With Data-Link Header
This example demonstrates how to **transmit a raw packet** on a live network.

The packet we will transmit looks like this:
```
Frame 1: 74 bytes on wire (592 bits), 74 bytes captured (592 bits)
Ethernet II, Src: ASUSTekC_b3:01:84 (00:1d:60:b3:01:84), Dst: Actionte_2f:47:87 (00:26:62:2f:47:87)
Internet Protocol Version 4, Src: 192.168.253.5, Dst: 192.168.253.6
Transmission Control Protocol, Src Port: 57678 (57678), Dst Port: http (80), Seq: 0, Len: 0
```
We use [Wireshark][wireshark] to convert a previously captured packet to a hex string (*`right click packet -> copy -> "... as a Hex Stream"`*) and then **jNetPcap's** utility method `PcapUtils.parseHexString()` to further convert into a java byte array, which we send as a raw packet:

```java
void main() throws PcapException {

	/* raw bytes of our packet, spaces ignored */
	final String ETHERNET = "0026622f4787 001d60b30184 0800";
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
This example produces no output, but if you monitor the network, you will see our non-routable packet being sent from the example host.

> **Note**! `Pcap.inject()` can also be used to transmit packets. We can also transmit data in `ByteBuffer` object, and a foreign native `MemorySegment`, all covered under advanced topics in [*wiki*][wiki].

### Statistics Snapshots
Our last example shows how to **take statistic snapshots** using `Pcap` API. The native *libpcap* library is able to capture statistics, even when our main thread is a sleep and only wakes up to take a snapshot of the current counters, store them in a `PcapStat` record and return them to our main thread. Then we simply print out the statistics structure values, sleep for 1 second and loop once again. For a total of 5 seconds or 5 loops.

```java
void main() throws PcapException, InterruptedException {
	List<PcapIf> devices = Pcap.findAllDevs();

	try (Pcap pcap = Pcap.create(devices.get(0))) {
		pcap.activate();

		long secondsRemaining = 5;

		while (secondsRemaining-- > 0) {
			PcapStat stats = pcap.stats();

			System.out.println(stats);

			TimeUnit.SECONDS.sleep(1);
		}
	}
}
```
Produces the following output:
```
PcapStatRecord[recv=0, drop=0, ifdrop=0, capt=0, sent=0, netdrop=0]
PcapStatRecord[recv=137, drop=0, ifdrop=0, capt=0, sent=0, netdrop=0]
PcapStatRecord[recv=340, drop=0, ifdrop=0, capt=0, sent=0, netdrop=0]
PcapStatRecord[recv=477, drop=0, ifdrop=0, capt=0, sent=0, netdrop=0]
PcapStatRecord[recv=677, drop=0, ifdrop=0, capt=0, sent=0, netdrop=0]
```

### How To Run The Examples
To run these exmamples the following command line arguments need to be added:
<dl><dt>On Linux platforms (<a href="https://installati.one/install-libpcap-dev-ubuntu-22-04/">How to install libpcap on Linux</a>)</dt><dd><pre><code>-Djava.library.path=/usr/lib/x86_64-linux-gnu --enable-native-access=org.jnetpcap --enable-preview</code></pre></dd>
	<dl><dt>On Windows platforms(<a href="https://npcap.com/#download">How to install Npcap on Windows</a>)</dt><dd><pre><code>-Djava.library.path=C:\Windows\SysWOW64 --enable-native-access=org.jnetpcap --enable-preview</pre></code></dd>
<dl><dt>On MacOS platforms (native libpcap installed via <a href="https://formulae.brew.sh/formula/libpcap">Homebrew</a>)</dt><dd><pre><code>-Djava.library.path=/usr/local/Cellar/libpcap/${VERSION}/lib --enable-native-access=org.jnetpcap --enable-preview</pre></code></dd>
<dl><dt>On MacOS platforms (native libpcap installed via <a href="https://ports.macports.org/port/libpcap/">Mac Ports</a>)</dt><dd><pre><code>-Djava.library.path=/opt/local/lib --enable-native-access=org.jnetpcap --enable-preview</pre></code></dd>
	
> **Note** that the `--enable-preview` command line option is only required until [*Foreign Function*][jep424] feature becomes permanent, possibly in [*JDK 21 LTS*][jdk_matrix].
	
### For more examples
See the [*wiki*] pages. Project's [unit tests][unit_test] are also a great source for usage examples of every single function in the module.

For extensive API usage examples, please see the dedicated [jnetpcap-examples](https://github.com/slytechs-repos/jnetpcap-examples) module.

## Dependencies
**jNetPcap** library has no external java dependencies except for modules provided by the java runtime.

### Java Dependencies for Module: `org.jnetpcap`
* No java dependencies except for standard java modules and the [*Foreign Function*][jep424] feature, currently in java *preview* (enabled with `--enable-preview` VM args option), but one which is expected to be a permanent feature, in the near future.

### Native Library Dependencies
* The only native dependency is the native [*libpcap* library][libpcap] itself, which has to be installed prior to **jNetPcap** module initializing. On *Microsoft Windows* platforms, install [*WinPcap*][winpcap] or [*Npcap*][npcap] tools instead.

## Installation
Here are several methods for installing **jNetPcap** software.

### Maven Artifact Config

![Maven Central Version](https://img.shields.io/maven-central/v/com.slytechs.jnet.jnetpcap/jnetpcap-wrapper)	
```xml
<dependency>
    <groupId>com.slytechs.jnet.jnetpcap</groupId>
    <artifactId>jnetpcap-wrapper</artifactId>
    <version>X.Y.Z</version>
</dependency>
```

> Using the latest version number released to [Maven Central][jnetpcap-maven-central]

### Using latest SNAPSHOT releases
Snapshot releases are more frequent development releases in between production releases. For stable code, we recommend not using snapshots, but if you want to checkout the latest updates, snapshots are available as well.

To access the latest SNAPSHOT release, add the following repository to your maven POM configuration:
```xml
<project>
  ...
  <repositories>
    <repository>
      <id>sonatype-snapshots</id>
      <name>Sonatype Snapshots</name>
      <url>https://oss.sonatype.org/content/repositories/snapshots</url>
      <snapshots>
        <enabled>true</enabled>
      </snapshots>
    </repository>
  </repositories>
  ...
</project>
```
then simply use the latest release with `-SNAPSHOT` appended to the version. This will download the latest SNAPSHOT release from the snapshot hosted on  `nexus/sonatype` servers

![Sonatype Nexus (Snapshots)](https://img.shields.io/nexus/s/com.slytechs.jnet.jnetpcap/jnetpcap-wrapper?server=https%3A%2F%2Fs01.oss.sonatype.org%2F)
```xml
<dependency>
    <groupId>com.slytechs.jnet.jnetpcap</groupId>
    <artifactId>jnetpcap-wrapper</artifactId>
    <version>X.Y.Z-SNAPSHOT</version>
</dependency>
```

### Download Release Package
Latest release: [*download link*][release]

### Compile From Source
You will find instructions on how to compile from source on our [*Wiki Pages*][wiki].

## Contact
* `sales@slytechs.com` for commercial and licensing questions
* [*jNetPcap Issue Tracker*][bugs]

## Compatibility with jNetPcap version 1
There are API and license changes between version 1 and 2 of **jNetPcap**.
Please see [*wiki*][wiki] home page for details.

## Git Branches
So everyone is on the same page, we follow the following [branching model][git-branch-model].

> **Note** 'main' branch replaces old 'master' branch references in document as per [Github recommendation][why-master-deprecated].

[jnetpcap_v1_page]: <https://sourceforge.net/projects/jnetpcap> "Legacy jNetPcap Version 1 Project Page"
[wiki]: <https://github.com/slytechs-repos/jnetpcap/wiki> "jNetPcap Project Wiki Pages"
[unit_test]: <https://github.com/slytechs-repos/jnetpcap/blob/main/src/test/java/org/jnetpcap/test/LibpcapApiTest.java> "jUnit Test of Main Libpcap API library"
[libpcap]: <https://www.tcpdump.org/> "This is the home web site of tcpdump, a powerful command-line packet analyzer; and libpcap, a portable C/C++ library for network traffic capture"
[npcap]: <https://npcap.com/> "Npcap is the Nmap Project's packet capture (and sending) library for Microsoft Windows"
[winpcap]: <https://www.winpcap.org/> "WinPcap is a library for link-layer network access in Windows environments"
[wireshark]: <https://wireshark.org> "Wireshark is the world’s foremost and widely-used network protocol analyzer"
[sf.net]: <https://sourceforge.net/projects/jnetpcap/> "jNetPcap version 1 hosted on SourceForge.net"
[bugs]: <https://github.com/slytechs-repos/jnetpcap/issues> "jnetPcap bug reports on Github"
[homebrew]: <https://formulae.brew.sh/formula/libpcap> "Native libpcap install on Mac/Osx using Homebrew"
[macports]: <https://ports.macports.org/port/libpcap/> "Native libpcap install on Mac/Osx using Mac Ports"
[javadocs]: <https://slytechs-repos.github.io/jnetpcap/apidocs/org.jnetpcap/org/jnetpcap/package-summary.html> "jNetPcap v2 reference documentation"
[release]: <https://github.com/slytechs-repos/jnetpcap/releases/tag/v2.0.0-alpha.1> "Latest jNetPcap v2 release"
[jdk_matrix]: <https://www.java.com/releases/fullmatrix/> "JDK release full matrix"
[jep424]: <https://openjdk.org/jeps/424> "Foreign Function & Memory API (Preview)"
[git-branch-model]: <https://nvie.com/posts/a-successful-git-branching-model>
[why-master-deprecated]: <https://www.theserverside.com/feature/Why-GitHub-renamed-its-master-branch-to-main>
[jnetpcap-sdk]: <https://github.com/slytechs-repos/jnetpcap-sdk>
[protocol-pack-sdk]: <https://github.com/slytechs-repos/protocol-pack-sdk>
[download-bundle]: <https://github.com/slytechs-repos/slytechs-repos/releases>
[protocol-packs]: <https://github.com/slytechs-repos/jnetpcap-pro/wiki#about-protocol-packs>
[jnetworks-sdk]: http://slytechs.com/jnetworks-sdk
[jnetpcap-maven-central]: <https://mvnrepository.com/artifact/com.slytechs.jnet.jnetpcap/jnetpcap-wrapper>
