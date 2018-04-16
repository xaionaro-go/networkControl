# networkControl

This's a library that provides an abstraction over FWSM and a Linux machine (to be used as router+dhcp+firewall) in a declarative way (you tell only how it should be, but not what to do). The project was created as an auxiliary library for [https://github.com/xaionaro-go/fwsmAPI](https://github.com/xaionaro-go/fwsmAPI).

## Dependencies

ATM, works only on Debian/Stretch

```sh
apt-get install iptables ipset isc-dhcp-server
```
## Post install

Add

```
128 fwsm
```

to `/etc/iproute2/rt_tables`

## ipset bug

Netfilter [hangs](https://bugzilla.kernel.org/show_bug.cgi?id=199107) if you do the next thing:

```sh
ipset create ACL.IN.ALL_PERMIT hash:net,iface hashsize 1048576 timeout 0
for i in $(seq 0 100); do
	/sbin/ipset add ACL.IN.ALL_PERMIT 0.0.0.0/0,kaf_$i timeout 0 -exist
done
```

Unfortunately this library does similar stuff, so you have to patch the kernel:

```
linux/net/netfilter/ipset/ip_set_core.c:
#define IP_SET_INC        2048

linux/net/netfilter/ipset/ip_set_hash_gen.h:
#define AHASH_MAX_TUNED                       2048
```

