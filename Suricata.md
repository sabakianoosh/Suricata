# **suricata**

**Suricata is an open-source, high-performance network threat detection engine. It is capable of performing deep packet inspection, network security monitoring, and intrusion detection/prevention (IDS/IPS). Developed by the Open Information Security Foundation (OISF), Suricata is widely used by organizations to enhance their network security posture.

**

****1. Intrusion Detection and Prevention (IDS/IPS):**

* Suricata can operate as both an intrusion detection system (IDS) and an intrusion prevention system (IPS).
* In IDS mode, it monitors network traffic and generates alerts based on predefined rules when suspicious activity is detected.
* In IPS mode, it can actively block or reject malicious traffic based on the same set of rules.

**

****2. Deep Packet Inspection (DPI):**

* Suricata performs deep packet inspection, analyzing the payload of packets beyond just the headers.
* This allows for detailed examination of network traffic and detection of malicious activity within the data payload.

**

****3. Protocol Identification and Analysis:**

* Suricata can automatically identify various protocols and analyze traffic accordingly.
* It supports protocols such as HTTP, DNS, TLS, FTP, SMB, and many others, enabling comprehensive analysis and detection capabilities.

**

****4. Multi-Threading and High Performance:**

* Suricata is designed to take advantage of modern multi-core processors, allowing for high-performance operation.
* This makes it suitable for monitoring large networks with high traffic volumes.

**

****5. Rule-Based Detection:**

* Suricata uses a rule-based language for defining detection patterns.
* It is compatible with Snort rules, allowing users to leverage existing rule sets and create custom rules.

**

****6. File Extraction and Analysis:**

* Suricata can extract files from network traffic for further analysis.
* This is useful for detecting malware, analyzing file transfers, and identifying suspicious file content.

**

****7. Integration with Other Tools:**

* Suricata can integrate with various security tools and platforms, such as SIEMs (Security Information and Event Management), logging frameworks, and visualization tools.
* It supports output formats like JSON, enabling easy integration and data sharing.

**

****8. Community and Support:**

* Being open-source, Suricata has a vibrant community of users and developers contributing to its continuous improvement.
* The OISF provides support, documentation, and training resources for users.

**

## Typical Use Cases

****1. Network Security Monitoring:**

* Suricata is used to continuously monitor network traffic for signs of malicious activity or policy violations.
* It provides real-time alerts and logs that help security teams respond to incidents quickly.

**

****2. Threat Detection:**

* Organizations deploy Suricata to detect various types of threats, including malware, exploits, and network attacks.
* Its ability to analyze traffic at the application layer allows for detecting sophisticated threats that might bypass simpler detection mechanisms.

**

****3. Intrusion Prevention:**

* In IPS mode, Suricata can actively block malicious traffic, preventing attacks from reaching their targets.
* This proactive defense helps protect critical network resources and data.

**

****4. Compliance and Auditing:**

* Suricata helps organizations meet regulatory requirements by monitoring and logging network activity.
* It provides detailed records that can be used for auditing and compliance reporting.

**

## Installation

```
sudo apt-get install software-properties-common
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata jq
```

After installing Suricata, you can check which version of Suricata you have running and with what options, as well as the service state:

```
sudo suricata --build-info
sudo systemctl status suricata
```

## Basic setup

First, determine the interface(s) and IP address(es) on which Suricata should be inspecting network packets:

```
$ ip addr

2: enp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff
inet 10.0.0.23/24 brd 10.23.0.255 scope global noprefixroute enp1s0
```

Use that information to configure Suricata:

```
sudo vim /etc/suricata/suricata.yaml
```

There are many possible configuration options, we focus on the setup of the `<span class="pre">HOME_NET</span>` variable and the network interface configuration. The `<span class="pre">HOME_NET</span>` variable should include, in most scenarios, the IP address of the monitored interface and all the local networks in use. The default already includes the RFC 1918 networks. In this example `<span class="pre">10.0.0.23</span>` is already included within `<span class="pre">10.0.0.0/8</span>`. If no other networks are used the other predefined values can be removed.

In this example the interface name is `<span class="pre">enp1s0</span>` so the interface name in the `<span class="pre">af-packet</span>` section needs to match. An example interface config might look like this:

```
af-packet:
- interface: enp1s0
```

## Signatures

Suricata uses Signatures to trigger alerts so it's necessary to install those and keep them updated. Signatures are also called rules, thus the name rule-files. With the tool `<span class="pre">suricata-update</span>` rules can be fetched, updated and managed to be provided for Suricata.

In this guide we just run the default mode which fetches the ET Open ruleset:

```
sudo suricata-update
```

Afterwards the rules are installed at `<span class="pre">/var/lib/suricata/rules</span>` which is also the default at the config and uses the sole `<span class="pre">suricata.rules</span>` file.

## Running Suricata

```
sudo systemctl restart suricata.service
```

```
sudo ls -al /var/log/suricata

total 7980
drwxr-xr-x  5 root root      4096 Jul 22 11:56 .
drwxrwxr-x 14 root syslog    4096 Jul 24 19:26 ..
drwxr-xr-x  2 root root      4096 Jun 27 19:41 certs
drwxr-xr-x  2 root root      4096 Jun 27 19:41 core
-rw-r--r--  1 root root   5009707 Jul 24 19:46 eve.json
-rw-r--r--  1 root root     18742 Jul 24 19:44 fast.log
drwxr-xr-x  2 root root      4096 Jun 27 19:41 files
-rw-r--r--  1 root root   2896392 Jul 24 19:46 stats.log
-rw-r--r--  1 root root    198931 Jul 24 19:26 suricata.log
-rw-r--r--  1 root root      1231 Jul 24 19:26 suricata-start.log

```

## Alerting

To test the IDS functionality of Suricata,add following code in `/var/lib/suricata/rules/local.rules`  and add local.rules in default rules path in yaml file.

```
alert icmp any any -> $HOME_NET any (msg : "ICMP ping"; sid:1; rev:1;)
```

now run ping in other window: `ping 8.8.8.8`

we can see the log with:

```
sudo cat /var/log/suricata/fast.log
```

more readable in json format:

```
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

Rule Breakdown:

**

**`alert`**:

* This specifies the action that Suricata should take when a packet matches the rule. In this case, "alert" means that Suricata will log an alert if the rule is triggered.

**

**

**`ip any any -> any any`**:

* **`ip`**: Indicates that the rule applies to all IP packets, regardless of the protocol (TCP, UDP, ICMP, etc.).
* **`any any` -> `any any`**:
  * The first `any any` specifies that the source IP address and port can be any value.
  * The `->` symbol indicates the direction of the traffic (from source to destination).
  * The second `any any` specifies that the destination IP address and port can also be any value.

**

fast.log contains the actual intrusion log store and eve.json save this in json format.

To run a quick test we can utilize one of the suricata rules that is included within the rules file

Default rule path is :

```
sudo ls -al /var/lib/surcata/rules
```


# Installation : source

**Compiling Suricata from source provides more control over the installation, allowing you to enable or disable specific features, optimize the build for your hardware, or apply custom patches.

**

```
tar xzvf suricata-6.0.0.tar.gz
cd suricata-6.0.0
./configure
make
make install
```



### Dependencies and compilation

```
sudo apt -y install autoconf automake build-essential cargo \
    cbindgen libjansson-dev libpcap-dev libpcre2-dev libtool \
    libyaml-dev make pkg-config rustc zlib1g-dev
```



#### Compilation

```
./configure # you may want to add additional parameters here
# ./configure --help to get all available parameters
# j is for adding concurrency to make; the number indicates how much
# concurrency so choose a number that is suitable for your build system
make -j8
make install # to install your Suricata compiled binary
# make install-full - installs configuration and rulesets as well
```



default rule path :

```
/usr/local/var/lib/suricata/rules
```

## Rules



### Rules Format


A rule/signature consists of the following:

* **The **action**,** determining what happens when the rule matches.
* **The **header****, defining the protocol, IP addresses, ports and direction of the rule.
* **The **rule options****, defining the specifics of the rule.

example:

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```

**alert** : action.

Valid actions are:

* alert - generate an alert.
* pass - stop further inspection of the packet.
* drop - drop packet and generate alert.
* reject - send RST/ICMP unreach error to the sender of the matching packet.
* rejectsrc - same as just reject.
* rejectdst - send RST/ICMP error packet to receiver of the matching packet.
* rejectboth - send RST/ICMP error packets to both sides of the conversation.


http : protocol

This keyword in a signature tells Suricata which protocol it concerns. You can choose between four basic protocols:

* tcp (for tcp-traffic)
* udp
* icmp
* ip (ip stands for 'all' or 'any')


HOME_NET and EXTERNAL_NET : source and destination

*The first emphasized part is the traffic source, the second is the traffic destination (note the direction of the directional arrow).*


any , any : Ports(source and destination)

*The first emphasized part is the source port, the second is the destination port (note the direction of the directional arrow).*

Traffic comes in and goes out through ports. Different protocols have different port numbers. For example, the default port for HTTP is 80 while 443 is typically the port for HTTPS. Note, however, that the port does not dictate which protocol is used in the communication. Rather, it determines which application is receiving the data.

The ports mentioned above are typically the destination ports. Source ports, i.e. the application that sent the packet, typically get assigned a random port by the operating system. When writing a rule for your own HTTP service, you would typically write `<span class="pre">any</span><span> </span><span class="pre">-></span><span> </span><span class="pre">80</span>`, since that would mean any packet from any source port to your HTTP application (running on port 80) is matched.
