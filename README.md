= networkControl

This's a library that provides an abstraction over FWSM and a Linux machine (to be used as router+dhcp+firewall). The project was created as an auxiliary library for [https://github.com/xaionaro-go/fwsmAPI](https://github.com/xaionaro-go/fwsmAPI).

=== Dependencies

ATM, works only on Debian/Stretch

```sh
apt-get install iptables ipset isc-dhcp-server
```

=== Post isntall

Add

```
128 fwsm
```

to `/etc/iproute2/rt_tables`

