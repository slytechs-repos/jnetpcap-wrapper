/**
 * Unit tests for jNetPcap library.
 * <p>
 * The following jUnit {@code @Tag} tags have been defined and can be used to
 * select which tests are to be executed by defining a property such as
 * {@code mvn test -Dgroups="live-capture"} or
 * {@code mvn test -DexcludeGroups="sudo-permission"}. Not restricting the maven
 * junit runner, will execute all tests.
 * <dl>
 * <dt>libpcap-api</dt>
 * <dd>selects tests that are generic libpcap, supported on all platforms</dd>
 * <dt>windows-api</dt>
 * <dd>selects tests that are only supported on Microsoft Windows platforms</dd>
 * <dt>linux-api</dt>
 * <dd>selects tests that are only supported on Linux platforms</dd>
 * <dt>Unix-api</dt>
 * <dd>selects test that are only supported on *nix platforms</dd>
 * <dt>non-libpcap-api</dt>
 * <dd>selects test that are non-libppcap methods but part of jNetPcap
 * library</dd>
 * <dt>live-capture</dt>
 * <dd>selects test which test live capture capabilities</dd>
 * <dt>offline-capture</dt>
 * <dd>selects tests which test offline capture capabilities</dd>
 * <dt>sudo-permission</dt>
 * <dd>selects tests which require super user permissions to run</dd>
 * <dt>user-permission</dt>
 * <dd>selects tests which will run using any non-privileged permission</dd>
 * <dt>live-network-with-packets</dt>
 * <dd>selects tests which do not produce reliable outcome because they are
 * dependent on live network conditions. We are testing a network packet capture
 * library after all, where some tests, that test capture or sending of live
 * packets are dependent on live network conditions. In this case, the actually
 * failure has to be closely examined to determine if the failure was do to
 * library failure or failure due to network conditions. These tests are
 * excluded from mvn testing by default.</dd>
 * <dt>libpcap-dumper-api</dt>
 * <dd>selects tests which use pcap dumper facilities and create temp dump capture files</dd>
 * </dl>
 * </p>
 */
package org.jnetpcap;