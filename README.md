# jNetPcap version 2
jNetPcap is a *libpcap* java binding. This is version 2 release of popular **jNetPcap** library, previously hosted on SourceForge.net.

### Compatibility with jNetPcap version 1
[Version 1  of **jNetPcap**][jnetpcap_v1_page] was released some 10 years ago. Version 2 has numerous backward incompatiblities with version 1, but overall version 1 based application can be easily upgraded to version 2.

Version 1  of **jNetPcap**, also bundled in a lot of functionality, that did not belong at the *libpcap* binding level. In version 2 all extraneous functinality has been factored out into separate modules, of which development does not have any impact on the main **jNetPcap** stability or functionality.

[jnetpcap_v1_page]: <https://sourceforge.net/projects/jnetpcap> "Legacy jNetPcap Version 1 Project Page"
## Overview
**jNetPcap** provides out of the box *libpcap* library bindings from *Java JRE*. By using *Foreign Function* features of *Java JRE*, jNetPcap can bind directly to all the native *libpcap* library functions and provides full functionality of underlying native *libpcap* library. All native *libpcap* functions, including legalcy *WinPcap* and latest *Npcap* libraries as well, on *Microsoft Windows* platforms. 

## Dependencies
**jNetPcap** binding has been designed to be extremely light and not have very few depdencies.

### Java Dependencies for Module: org.jnetpcap
* No java dependencies except for standard java modules and the *Foreign Function* feature, currently in java *preview*, but one which is expected to be a permanent feature, in the near future.

### Native libbrary depdencies
* The only native dependency is the native *libpcap* library itself, which has to be installed prior to **jNetPcap** module initializing. All versions of *libpcap* API are supported, from *libpcap* version 0.4 to the current latest version 1.5. This also includes the latest *WinPcap* and *Npcap* derivatives on *Microsfot Windows* platforms.
## Installation
For now, deployment and is done using Maven2 repositories
## Maven installation
* **groupid:** org.jnetpcap
* **artifactId:** jnetpcap
* **version:** 2.0.0-preview.1
## Related Modules
Previously embeded functionality into **jNetPcap** version 1, has be refactored into a separate modules. 
### Module: org.jnetpcap.packet
Provides high level packet dissecting and decoding functionality. It requires 'org.jnetpcap' module, and has several other depdencies (listed in the 'jnetpcap-packet' repo.)
**Todo:** add link to jnetpcap-packet module
## Usage
See this repos wiki pages and accompanied Javadocs
