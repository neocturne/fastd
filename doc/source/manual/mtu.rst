MTU configuration
=================
The default MTU of fastd is 1500. This allows briding the fastd interface in TAP
mode with other interface with the same MTU, but will usually cause fastd's UDP
packets to be fragmented. Fragmentation can lower the
performance or even cause connectivity problems when broken routers filter ICMP packets,
so if possible the MTU should be chosed small enough so that IP fragmentation can be avoided.
Unlike OpenVPN, fastd doesn't support fragmentation itself, but relies on the IP stack to fragment packets when necessary.

Guidelines
----------

* The basic overhead of a fastd packet in TUN mode over IPv4 is 39 Bytes when only null crypto is used and 52 Bytes for all other crypto methods
* TAP mode needs 14 bytes more than TUN mode
* Tunneling over IPv6 needs 20 bytes more than IPv4

Examples
--------

Your base MTU is 1500 and you want to use TUN mode over IPv4 with any crypto method:
  Choose 1500 - 52 = 1448 bytes.

Your base MTU is 1492 (like most German DSL lines) and you want to use TAP mode over IPv4 with any crypto method:
  Choose 1492 - 52 - 14 = 1426 bytes.

Conservative choice when you want to transfer IPv6 inside the tunnel:
  Choose 1280 Bytes (not relevant when you use batman-adv inside the tunnel as batman-adv will take care of the inner fragmentation).

Conservative choice when you don't know anything (but assume the base MTU is at least 1280 so IPv6 can be supported) and want to support tunnels over IPv4 and IPv6 in TAP mode with any crypto method:
  Choose 1280 - 52 - 14 - 20 = 1194 bytes.
