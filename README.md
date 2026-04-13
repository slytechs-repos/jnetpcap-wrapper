# jNetPcap Bindings

[![Java](https://img.shields.io/badge/Java-22%2B-orange.svg)](https://openjdk.java.net/projects/jdk/22/) [![Panama FFM](https://img.shields.io/badge/Panama-Foreign%20Memory-blue.svg)](https://openjdk.java.net/projects/panama/) [![Maven Central](https://img.shields.io/badge/Maven-Central-blue.svg)](https://search.maven.org/artifact/com.slytechs.sdk/jnetpcap-bindings) [![License](https://img.shields.io/badge/License-Apache%20v2-green.svg)](https://claude.ai/chat/LICENSE)

Low-level libpcap bindings for Java using Panama Foreign Function & Memory API.

**jNetPcap Bindings** provides direct access to [libpcap](https://www.tcpdump.org/) from Java via the Panama FFM API. This is the **version 3** release of the popular **jNetPcap** library, originally hosted on [SourceForge.net](https://sourceforge.net/projects/jnetpcap/).

> **Note**: Version 3 uses Panama FFM (not JNI). Requires JDK 22+.

------

## Table of Contents

1. [Overview](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#overview)
2. [Architecture](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#architecture)
3. [Quick Start](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#quick-start)
4. [Examples](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#examples)
5. [Dependencies](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#dependencies)
6. [Installation](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#installation)
7. [Documentation](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#documentation)
8. [Contact](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#contact)
9. [Migration from v1/v2](https://claude.ai/chat/2b3c34b0-d15b-43e9-95df-1d214208b87d#migration-from-v1v2)

------

## Overview

Direct libpcap access from Java using Panama Foreign Function & Memory API for zero-overhead native calls.

**Key Features:**

- **Zero-Overhead Native Calls** - Panama FFM provides near-native performance
- **Type-Safe Bindings** - Java-friendly API wrapping libpcap functions
- **Memory Safety** - Automatic resource management via Arena scopes
- **Cross-Platform** - Linux, Windows (Npcap/WinPcap), macOS

------

## Architecture

```
┌─────────────────────────┐
│    Java Application     │
└───────────┬─────────────┘
            │
┌───────────▼─────────────┐
│   jnetpcap-bindings     │  ◄── This module
│   (Panama FFM API)      │
└───────────┬─────────────┘
            │
┌───────────▼─────────────┐
│  libpcap / Npcap        │
└───────────┬─────────────┘
            │
┌───────────▼─────────────┐
│   Operating System      │
└───────────┬─────────────┘
            │
┌───────────▼─────────────┐
│  Network Interface      │
└─────────────────────────┘
```

For higher-level packet capture and protocol analysis, see [jnetpcap-api](https://github.com/slytechs-repos/jnetpcap-api) and [jnetpcap-sdk](https://github.com/slytechs-repos/jnetpcap-sdk).

------

## Quick Start

### Using SDK BOM (Recommended)

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.slytechs.sdk</groupId>
            <artifactId>sdk-bom</artifactId>
            <version>3.0.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <dependency>
        <groupId>com.slytechs.sdk</groupId>
        <artifactId>jnetpcap-bindings</artifactId>
    </dependency>
</dependencies>
```

### Module Declaration

```java
module your.module {
    requires com.slytechs.jnet.jnetpcap;
}
```

------

## Examples

### Capture a Live Packet

```java
void main() throws PcapException {
    List<PcapIf> devices = Pcap.findAllDevs();
    
    try (Pcap pcap = Pcap.create(devices.getFirst())) {
        pcap.activate();
        
        pcap.loop(1, (String msg, PcapHeader header, byte[] packet) -> {
            System.out.printf("Captured %d bytes%n", header.captureLength());
        }, "Capture Example");
    }
}
```

### Transmit a Packet

```java
void main() throws PcapException {
    byte[] packetBytes = HexStrings.parseHexString("0026622f4787...");
    List<PcapIf> devices = Pcap.findAllDevs();
    
    try (Pcap pcap = Pcap.create(devices.getFirst())) {
        pcap.activate();
        pcap.sendPacket(packetBytes);
    }
}
```

### Statistics Snapshots

```java
void main() throws PcapException, InterruptedException {
    List<PcapIf> devices = Pcap.findAllDevs();
    
    try (Pcap pcap = Pcap.create(devices.getFirst())) {
        pcap.activate();
        
        for (int i = 0; i < 5; i++) {
            System.out.println(pcap.stats());
            Thread.sleep(1000);
        }
    }
}
```

### JVM Arguments

```bash
java --enable-native-access=com.slytechs.jnet.jnetpcap \
     -Djava.library.path=/usr/lib \
     -jar your-app.jar
```

------

## Dependencies

### Java Requirements

- **JDK 22+** - Required for Panama FFM API

### Native Library Requirements

One of:

- [libpcap](https://www.tcpdump.org/) (Linux/macOS)
- [Npcap](https://npcap.com/) (Windows, recommended)
- [WinPcap](https://www.winpcap.org/) (Windows, legacy)

------

## Installation

### Maven (with BOM)

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.slytechs.sdk</groupId>
            <artifactId>sdk-bom</artifactId>
            <version>3.0.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <dependency>
        <groupId>com.slytechs.sdk</groupId>
        <artifactId>jnetpcap-bindings</artifactId>
    </dependency>
</dependencies>
```

### Maven (standalone)

```xml
<dependency>
    <groupId>com.slytechs.sdk</groupId>
    <artifactId>jnetpcap-bindings</artifactId>
    <version>3.0.0</version>
</dependency>
```

### Gradle

```groovy
dependencies {
    implementation platform('com.slytechs.sdk:sdk-bom:3.0.0')
    implementation 'com.slytechs.sdk:jnetpcap-bindings'
}
```

------

## Documentation

- [GitHub Wiki](https://github.com/slytechs-repos/jnetpcap-bindings/wiki) - User guides and examples
- [Javadocs](https://slytechs-repos.github.io/jnetpcap-bindings/) - API documentation
- [SDK BOM](https://github.com/slytechs-repos/sdk-bom) - Version management

------

## Contact

- **Email:** sales@slytechs.com
- **Website:** [www.slytechs.com](https://www.slytechs.com/)

------

## Migration from v1/v2

### Key Changes in v3

| Aspect             | v1/v2                        | v3                           |
| ------------------ | ---------------------------- | ---------------------------- |
| Native integration | JNI                          | Panama FFM                   |
| Java version       | 8-11                         | 22+                          |
| Maven groupId      | `com.slytechs.jnet.jnetpcap` | `com.slytechs.sdk`           |
| Maven artifactId   | `jnetpcap-wrapper`           | `jnetpcap-bindings`          |
| Module name        | `com.slytechs.sdk.jnetpcap`               | `com.slytechs.jnet.jnetpcap` |

### Protocol Support

Protocol dissection (Ethernet, IP, TCP, etc.) is available via separate modules:

- [sdk-protocol-tcpip](https://github.com/slytechs-repos/sdk-protocol-tcpip) - TCP/IP stack
- [sdk-protocol-web](https://github.com/slytechs-repos/sdk-protocol-web) - Web protocols
- [jnetpcap-api](https://github.com/slytechs-repos/jnetpcap-api) - High-level capture API
- [jnetpcap-sdk](https://github.com/slytechs-repos/jnetpcap-sdk) - Complete SDK starter

For detailed migration instructions, see the [Wiki](https://github.com/slytechs-repos/jnetpcap-bindings/wiki).

------

## Related Projects

- [jnetpcap-api](https://github.com/slytechs-repos/jnetpcap-api) - High-level packet capture API
- [jnetpcap-sdk](https://github.com/slytechs-repos/jnetpcap-sdk) - Complete SDK starter (recommended)
- [sdk-protocol-tcpip](https://github.com/slytechs-repos/sdk-protocol-tcpip) - TCP/IP protocol pack
- [sdk-common](https://github.com/slytechs-repos/sdk-common) - Core utilities

------

**Sly Technologies Inc.** - High-performance network analysis solutions

Website: [www.slytechs.com](https://www.slytechs.com/)

------
