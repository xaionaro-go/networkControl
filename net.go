package networkControl

import (
	"fmt"
	"github.com/xaionaro-go/handySlices"
	"net"
	"sort"
	"strconv"
	"strings"
)

type Protocol int

type IPPort struct {
	Protocol *Protocol
	IP       net.IP
	Port     *uint16
}

type PortRange struct {
	Start uint16
	End   uint16
}

type IPs []net.IP
type IPNet net.IPNet
type IPNets []IPNet
type IPPorts []IPPort
type NSs []net.NS
type PortRanges []PortRange
type Domain string

func (a IPPorts) Len() int           { return len(a) }
func (a IPPorts) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a IPPorts) Less(i, j int) bool { return strings.Compare(a[i].String(), a[j].String()) < 0 }

func (ipports *IPPorts) Sort() IPPorts {
	sort.Sort(*ipports)
	return *ipports
}
func (ipports IPPorts) String() string {
	return fmt.Sprintf("%v", ([]IPPort)(ipports))
}

func (ipport *IPPort) Parse(str string) {
	if len(str) == 0 {
		return
	}
	words := strings.Split(str, ":")
	ipport.IP = net.ParseIP(words[0])
	if len(words) > 1 {
		port, err := strconv.Atoi(words[1])
		if err != nil {
			panic(err)
		}
		port16 := uint16(port)
		ipport.Port = &port16
	}
	return
}

func (ipnet IPNet) Contains(ip net.IP) bool {
	return (*net.IPNet)(&ipnet).Contains(ip)
}

func (ips IPs) IsEqualTo(compareTo IPs) bool {
	return handySlices.IsEqualCollections(ips, compareTo)
}
func (ipnets IPNets) IsEqualToI(compareToI handySlices.IsEqualToIer) bool {
	return ipnets.IsEqualTo(compareToI.(IPNets))
}
func (ipnets IPNets) IsEqualTo(compareTo IPNets) bool {
	return handySlices.IsEqualCollections(ipnets, compareTo)
}
func (ipnet IPNet) IsEqualToI(compareToI handySlices.IsEqualToIer) bool {
	return ipnet.IsEqualTo(compareToI.(IPNet))
}
func (ipnet IPNet) IsEqualTo(compareTo IPNet) bool {
	return ipnet.String() == compareTo.String()
}

func IPNetFromCIDRString(cidrString string) (ipnet IPNet, err error) {
	var ipnetRaw *net.IPNet
	_, ipnetRaw, err = net.ParseCIDR(cidrString)
	if err != nil {
		return
	}
	ipnet = IPNet(*ipnetRaw)
	return
}

func (ipnet IPNet) String() string {
	t := net.IPNet(ipnet)
	return t.String()
}

func IPNetUnmaskedFromStrings(ipStr string, maskStr string) (ipnet IPNet, err error) {
	ipnet.IP = net.ParseIP(ipStr)
	ipnet.Mask = net.IPMask(net.ParseIP(maskStr))

	return
}

func IPNetFromStrings(ipStr string, maskStr string) (ipnet IPNet, err error) {
	ipnet, err = IPNetUnmaskedFromStrings(ipStr, maskStr)
	ipnet.IP = ipnet.IP.Mask(ipnet.Mask)

	return
}

func PortFromString(portStr string) uint16 {
	// sed -e 's/#.*//g' /etc/services | awk '{if($1 == "" || alreadySet[$1] == 1){next}; gsub("/.*", "", $2); print "case \""$1"\": return "$2; alreadySet[$1]=1; if(alreadySet[$3] ==1 ){next}  if ($3 != ""){print "case \""$3"\": return "$2;}  alreadySet[$3]=1}'; echo 'case "imap4": return 143'; echo 'case "pptp": return 1723'

	switch portStr {
	case "tcpmux":
		return 1
	case "echo":
		return 7
	case "discard":
		return 9
	case "sink":
		return 9
	case "systat":
		return 11
	case "users":
		return 11
	case "daytime":
		return 13
	case "netstat":
		return 15
	case "qotd":
		return 17
	case "quote":
		return 17
	case "msp":
		return 18
	case "chargen":
		return 19
	case "ttytst":
		return 19
	case "ftp-data":
		return 20
	case "ftp":
		return 21
	case "fsp":
		return 21
	case "fspd":
		return 21
	case "ssh":
		return 22
	case "telnet":
		return 23
	case "smtp":
		return 25
	case "mail":
		return 25
	case "time":
		return 37
	case "timserver":
		return 37
	case "rlp":
		return 39
	case "resource":
		return 39
	case "nameserver":
		return 42
	case "name":
		return 42
	case "whois":
		return 43
	case "nicname":
		return 43
	case "tacacs":
		return 49
	case "re-mail-ck":
		return 50
	case "domain":
		return 53
	case "tacacs-ds":
		return 65
	case "bootps":
		return 67
	case "bootpc":
		return 68
	case "tftp":
		return 69
	case "gopher":
		return 70
	case "finger":
		return 79
	case "http":
		return 80
	case "www":
		return 80
	case "link":
		return 87
	case "ttylink":
		return 87
	case "kerberos":
		return 88
	case "kerberos5":
		return 88
	case "supdup":
		return 95
	case "hostnames":
		return 101
	case "hostname":
		return 101
	case "iso-tsap":
		return 102
	case "tsap":
		return 102
	case "acr-nema":
		return 104
	case "dicom":
		return 104
	case "csnet-ns":
		return 105
	case "cso-ns":
		return 105
	case "rtelnet":
		return 107
	case "pop3":
		return 110
	case "pop-3":
		return 110
	case "sunrpc":
		return 111
	case "portmapper":
		return 111
	case "auth":
		return 113
	case "authentication":
		return 113
	case "sftp":
		return 115
	case "nntp":
		return 119
	case "readnews":
		return 119
	case "ntp":
		return 123
	case "pwdgen":
		return 129
	case "loc-srv":
		return 135
	case "epmap":
		return 135
	case "netbios-ns":
		return 137
	case "netbios-dgm":
		return 138
	case "netbios-ssn":
		return 139
	case "imap2":
		return 143
	case "imap":
		return 143
	case "snmp":
		return 161
	case "snmp-trap":
		return 162
	case "snmptrap":
		return 162
	case "cmip-man":
		return 163
	case "cmip-agent":
		return 164
	case "mailq":
		return 174
	case "xdmcp":
		return 177
	case "nextstep":
		return 178
	case "NeXTStep":
		return 178
	case "bgp":
		return 179
	case "irc":
		return 194
	case "smux":
		return 199
	case "at-rtmp":
		return 201
	case "at-nbp":
		return 202
	case "at-echo":
		return 204
	case "at-zis":
		return 206
	case "qmtp":
		return 209
	case "z3950":
		return 210
	case "wais":
		return 210
	case "ipx":
		return 213
	case "pawserv":
		return 345
	case "zserv":
		return 346
	case "fatserv":
		return 347
	case "rpc2portmap":
		return 369
	case "codaauth2":
		return 370
	case "clearcase":
		return 371
	case "Clearcase":
		return 371
	case "ulistserv":
		return 372
	case "ldap":
		return 389
	case "imsp":
		return 406
	case "svrloc":
		return 427
	case "https":
		return 443
	case "snpp":
		return 444
	case "microsoft-ds":
		return 445
	case "kpasswd":
		return 464
	case "urd":
		return 465
	case "ssmtp":
		return 465
	case "saft":
		return 487
	case "isakmp":
		return 500
	case "rtsp":
		return 554
	case "nqs":
		return 607
	case "npmp-local":
		return 610
	case "dqs313_qmaster":
		return 610
	case "npmp-gui":
		return 611
	case "dqs313_execd":
		return 611
	case "hmmp-ind":
		return 612
	case "dqs313_intercell":
		return 612
	case "asf-rmcp":
		return 623
	case "qmqp":
		return 628
	case "ipp":
		return 631
	case "exec":
		return 512
	case "biff":
		return 512
	case "comsat":
		return 512
	case "login":
		return 513
	case "who":
		return 513
	case "whod":
		return 513
	case "shell":
		return 514
	case "cmd":
		return 514
	case "syslog":
		return 514
	case "printer":
		return 515
	case "spooler":
		return 515
	case "talk":
		return 517
	case "ntalk":
		return 518
	case "route":
		return 520
	case "router":
		return 520
	case "timed":
		return 525
	case "timeserver":
		return 525
	case "tempo":
		return 526
	case "newdate":
		return 526
	case "courier":
		return 530
	case "rpc":
		return 530
	case "conference":
		return 531
	case "chat":
		return 531
	case "netnews":
		return 532
	case "netwall":
		return 533
	case "gdomap":
		return 538
	case "uucp":
		return 540
	case "uucpd":
		return 540
	case "klogin":
		return 543
	case "kshell":
		return 544
	case "krcmd":
		return 544
	case "dhcpv6-client":
		return 546
	case "dhcpv6-server":
		return 547
	case "afpovertcp":
		return 548
	case "idfp":
		return 549
	case "remotefs":
		return 556
	case "rfs_server":
		return 556
	case "nntps":
		return 563
	case "snntp":
		return 563
	case "submission":
		return 587
	case "ldaps":
		return 636
	case "tinc":
		return 655
	case "silc":
		return 706
	case "kerberos-adm":
		return 749
	case "webster":
		return 765
	case "rsync":
		return 873
	case "ftps-data":
		return 989
	case "ftps":
		return 990
	case "telnets":
		return 992
	case "imaps":
		return 993
	case "pop3s":
		return 995
	case "socks":
		return 1080
	case "proofd":
		return 1093
	case "rootd":
		return 1094
	case "openvpn":
		return 1194
	case "rmiregistry":
		return 1099
	case "kazaa":
		return 1214
	case "nessus":
		return 1241
	case "lotusnote":
		return 1352
	case "lotusnotes":
		return 1352
	case "ms-sql-s":
		return 1433
	case "ms-sql-m":
		return 1434
	case "ingreslock":
		return 1524
	case "datametrics":
		return 1645
	case "old-radius":
		return 1645
	case "sa-msg-port":
		return 1646
	case "old-radacct":
		return 1646
	case "kermit":
		return 1649
	case "groupwise":
		return 1677
	case "l2f":
		return 1701
	case "l2tp":
		return 1701
	case "radius":
		return 1812
	case "radius-acct":
		return 1813
	case "radacct":
		return 1813
	case "msnp":
		return 1863
	case "unix-status":
		return 1957
	case "log-server":
		return 1958
	case "remoteping":
		return 1959
	case "cisco-sccp":
		return 2000
	case "search":
		return 2010
	case "ndtp":
		return 2010
	case "pipe-server":
		return 2010
	case "pipe_server":
		return 2010
	case "nfs":
		return 2049
	case "gnunet":
		return 2086
	case "rtcm-sc104":
		return 2101
	case "gsigatekeeper":
		return 2119
	case "gris":
		return 2135
	case "cvspserver":
		return 2401
	case "venus":
		return 2430
	case "venus-se":
		return 2431
	case "codasrv":
		return 2432
	case "codasrv-se":
		return 2433
	case "mon":
		return 2583
	case "dict":
		return 2628
	case "f5-globalsite":
		return 2792
	case "gsiftp":
		return 2811
	case "gpsd":
		return 2947
	case "gds-db":
		return 3050
	case "gds_db":
		return 3050
	case "icpv2":
		return 3130
	case "icp":
		return 3130
	case "isns":
		return 3205
	case "iscsi-target":
		return 3260
	case "mysql":
		return 3306
	case "nut":
		return 3493
	case "distcc":
		return 3632
	case "daap":
		return 3689
	case "svn":
		return 3690
	case "subversion":
		return 3690
	case "suucp":
		return 4031
	case "sysrqd":
		return 4094
	case "sieve":
		return 4190
	case "epmd":
		return 4369
	case "remctl":
		return 4373
	case "f5-iquery":
		return 4353
	case "ipsec-nat-t":
		return 4500
	case "iax":
		return 4569
	case "mtn":
		return 4691
	case "radmin-port":
		return 4899
	case "rfe":
		return 5002
	case "mmcc":
		return 5050
	case "sip":
		return 5060
	case "sip-tls":
		return 5061
	case "aol":
		return 5190
	case "xmpp-client":
		return 5222
	case "jabber-client":
		return 5222
	case "xmpp-server":
		return 5269
	case "jabber-server":
		return 5269
	case "cfengine":
		return 5308
	case "mdns":
		return 5353
	case "postgresql":
		return 5432
	case "postgres":
		return 5432
	case "freeciv":
		return 5556
	case "rptp":
		return 5556
	case "amqps":
		return 5671
	case "amqp":
		return 5672
	case "ggz":
		return 5688
	case "x11":
		return 6000
	case "x11-0":
		return 6000
	case "x11-1":
		return 6001
	case "x11-2":
		return 6002
	case "x11-3":
		return 6003
	case "x11-4":
		return 6004
	case "x11-5":
		return 6005
	case "x11-6":
		return 6006
	case "x11-7":
		return 6007
	case "gnutella-svc":
		return 6346
	case "gnutella-rtr":
		return 6347
	case "sge-qmaster":
		return 6444
	case "sge_qmaster":
		return 6444
	case "sge-execd":
		return 6445
	case "sge_execd":
		return 6445
	case "mysql-proxy":
		return 6446
	case "babel":
		return 6696
	case "ircs-u":
		return 6697
	case "afs3-fileserver":
		return 7000
	case "bbs":
		return 7000
	case "afs3-callback":
		return 7001
	case "afs3-prserver":
		return 7002
	case "afs3-vlserver":
		return 7003
	case "afs3-kaserver":
		return 7004
	case "afs3-volser":
		return 7005
	case "afs3-errors":
		return 7006
	case "afs3-bos":
		return 7007
	case "afs3-update":
		return 7008
	case "afs3-rmtsys":
		return 7009
	case "font-service":
		return 7100
	case "xfs":
		return 7100
	case "http-alt":
		return 8080
	case "webcache":
		return 8080
	case "puppet":
		return 8140
	case "bacula-dir":
		return 9101
	case "bacula-fd":
		return 9102
	case "bacula-sd":
		return 9103
	case "xmms2":
		return 9667
	case "nbd":
		return 10809
	case "zabbix-agent":
		return 10050
	case "zabbix-trapper":
		return 10051
	case "amanda":
		return 10080
	case "hkp":
		return 11371
	case "bprd":
		return 13720
	case "bpdbm":
		return 13721
	case "bpjava-msvc":
		return 13722
	case "vnetd":
		return 13724
	case "bpcd":
		return 13782
	case "vopied":
		return 13783
	case "db-lsp":
		return 17500
	case "dcap":
		return 22125
	case "gsidcap":
		return 22128
	case "wnn6":
		return 22273
	case "rtmp":
		return 1
	case "nbp":
		return 2
	case "zip":
		return 6
	case "kerberos4":
		return 750
	case "kerberos-iv":
		return 750
	case "kerberos-master":
		return 751
	case "kerberos_master":
		return 751
	case "passwd-server":
		return 752
	case "passwd_server":
		return 752
	case "krb-prop":
		return 754
	case "krb_prop":
		return 754
	case "krbupdate":
		return 760
	case "kreg":
		return 760
	case "swat":
		return 901
	case "kpop":
		return 1109
	case "knetd":
		return 2053
	case "zephyr-srv":
		return 2102
	case "zephyr-clt":
		return 2103
	case "zephyr-hm":
		return 2104
	case "eklogin":
		return 2105
	case "kx":
		return 2111
	case "iprop":
		return 2121
	case "supfilesrv":
		return 871
	case "supfiledbg":
		return 1127
	case "linuxconf":
		return 98
	case "poppassd":
		return 106
	case "moira-db":
		return 775
	case "moira_db":
		return 775
	case "moira-update":
		return 777
	case "moira_update":
		return 777
	case "moira-ureg":
		return 779
	case "moira_ureg":
		return 779
	case "spamd":
		return 783
	case "omirr":
		return 808
	case "omirrd":
		return 808
	case "customs":
		return 1001
	case "skkserv":
		return 1178
	case "predict":
		return 1210
	case "rmtcfg":
		return 1236
	case "wipld":
		return 1300
	case "xtel":
		return 1313
	case "xtelw":
		return 1314
	case "support":
		return 1529
	case "cfinger":
		return 2003
	case "frox":
		return 2121
	case "ninstall":
		return 2150
	case "zebrasrv":
		return 2600
	case "zebra":
		return 2601
	case "ripd":
		return 2602
	case "ripngd":
		return 2603
	case "ospfd":
		return 2604
	case "bgpd":
		return 2605
	case "ospf6d":
		return 2606
	case "ospfapi":
		return 2607
	case "isisd":
		return 2608
	case "afbackup":
		return 2988
	case "afmbackup":
		return 2989
	case "xtell":
		return 4224
	case "fax":
		return 4557
	case "hylafax":
		return 4559
	case "distmp3":
		return 4600
	case "munin":
		return 4949
	case "lrrd":
		return 4949
	case "enbd-cstatd":
		return 5051
	case "enbd-sstatd":
		return 5052
	case "pcrd":
		return 5151
	case "noclog":
		return 5354
	case "hostmon":
		return 5355
	case "rplay":
		return 5555
	case "nrpe":
		return 5666
	case "nsca":
		return 5667
	case "mrtd":
		return 5674
	case "bgpsim":
		return 5675
	case "canna":
		return 5680
	case "syslog-tls":
		return 6514
	case "sane-port":
		return 6566
	case "sane":
		return 6566
	case "ircd":
		return 6667
	case "zope-ftp":
		return 8021
	case "tproxy":
		return 8081
	case "omniorb":
		return 8088
	case "clc-build-daemon":
		return 8990
	case "xinetd":
		return 9098
	case "mandelspawn":
		return 9359
	case "mandelbrot":
		return 9359
	case "git":
		return 9418
	case "zope":
		return 9673
	case "webmin":
		return 10000
	case "kamanda":
		return 10081
	case "amandaidx":
		return 10082
	case "amidxtape":
		return 10083
	case "smsqp":
		return 11201
	case "xpilot":
		return 15345
	case "sgi-cmsd":
		return 17001
	case "sgi-crsd":
		return 17002
	case "sgi-gcd":
		return 17003
	case "sgi-cad":
		return 17004
	case "isdnlog":
		return 20011
	case "vboxd":
		return 20012
	case "binkp":
		return 24554
	case "asp":
		return 27374
	case "csync2":
		return 30865
	case "dircproxy":
		return 57000
	case "tfido":
		return 60177
	case "fido":
		return 60179
	case "imap4":
		return 143
	case "pptp":
		return 1723

	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		panic(err)
	}

	return uint16(port)
}

func ProtocolFromString(protocolStr string) Protocol {
	// awk 'BEGIN{prevId=-1} {if($1 == "#" || $1 == "" || $2 <= prevId){next} gsub("[-.]", "", $1) ;print "case \""$1"\": return PROTO_"toupper($1); prevId=$2}' < /etc/protocols
	switch protocolStr {
	case "ip":
		return PROTO_IP
	case "icmp":
		return PROTO_ICMP
	case "igmp":
		return PROTO_IGMP
	case "ggp":
		return PROTO_GGP
	case "ipencap":
		return PROTO_IPENCAP
	case "st":
		return PROTO_ST
	case "tcp":
		return PROTO_TCP
	case "egp":
		return PROTO_EGP
	case "igp":
		return PROTO_IGP
	case "pup":
		return PROTO_PUP
	case "udp":
		return PROTO_UDP
	case "hmp":
		return PROTO_HMP
	case "xnsidp":
		return PROTO_XNSIDP
	case "rdp":
		return PROTO_RDP
	case "isotp4":
		return PROTO_ISOTP4
	case "dccp":
		return PROTO_DCCP
	case "xtp":
		return PROTO_XTP
	case "ddp":
		return PROTO_DDP
	case "idprcmtp":
		return PROTO_IDPRCMTP
	case "ipv6":
		return PROTO_IPV6
	case "ipv6route":
		return PROTO_IPV6ROUTE
	case "ipv6frag":
		return PROTO_IPV6FRAG
	case "idrp":
		return PROTO_IDRP
	case "rsvp":
		return PROTO_RSVP
	case "gre":
		return PROTO_GRE
	case "esp":
		return PROTO_ESP
	case "ah":
		return PROTO_AH
	case "skip":
		return PROTO_SKIP
	case "ipv6icmp":
		return PROTO_IPV6ICMP
	case "ipv6nonxt":
		return PROTO_IPV6NONXT
	case "ipv6opts":
		return PROTO_IPV6OPTS
	case "rspf":
		return PROTO_RSPF
	case "vmtp":
		return PROTO_VMTP
	case "eigrp":
		return PROTO_EIGRP
	case "ospf":
		return PROTO_OSPF
	case "ax25":
		return PROTO_AX25
	case "ipip":
		return PROTO_IPIP
	case "etherip":
		return PROTO_ETHERIP
	case "encap":
		return PROTO_ENCAP
	case "pim":
		return PROTO_PIM
	case "ipcomp":
		return PROTO_IPCOMP
	case "vrrp":
		return PROTO_VRRP
	case "l2tp":
		return PROTO_L2TP
	case "isis":
		return PROTO_ISIS
	case "sctp":
		return PROTO_SCTP
	case "fc":
		return PROTO_FC
	case "mobilityheader":
		return PROTO_MOBILITYHEADER
	case "udplite":
		return PROTO_UDPLITE
	case "mplsinip":
		return PROTO_MPLSINIP
	case "manet":
		return PROTO_MANET
	case "hip":
		return PROTO_HIP
	case "shim6":
		return PROTO_SHIM6
	case "wesp":
		return PROTO_WESP
	case "rohc":
		return PROTO_ROHC
	}

	panic("Unknown protocol: <" + protocolStr + ">")
	return PROTO_IP
}

func (protocol Protocol) String() string {
	switch protocol {
	// awk 'BEGIN{prevId=-1} {if($1 == "#" || $1 == "" || $2 <= prevId){next} gsub("[-.]", "", $1) ;print "case PROTO_"toupper($1)": return \""$1"\""; prevId=$2}' < /etc/protocols
	case PROTO_IP:
		return "ip"
	case PROTO_ICMP:
		return "icmp"
	case PROTO_IGMP:
		return "igmp"
	case PROTO_GGP:
		return "ggp"
	case PROTO_IPENCAP:
		return "ipencap"
	case PROTO_ST:
		return "st"
	case PROTO_TCP:
		return "tcp"
	case PROTO_EGP:
		return "egp"
	case PROTO_IGP:
		return "igp"
	case PROTO_PUP:
		return "pup"
	case PROTO_UDP:
		return "udp"
	case PROTO_HMP:
		return "hmp"
	case PROTO_XNSIDP:
		return "xnsidp"
	case PROTO_RDP:
		return "rdp"
	case PROTO_ISOTP4:
		return "isotp4"
	case PROTO_DCCP:
		return "dccp"
	case PROTO_XTP:
		return "xtp"
	case PROTO_DDP:
		return "ddp"
	case PROTO_IDPRCMTP:
		return "idprcmtp"
	case PROTO_IPV6:
		return "ipv6"
	case PROTO_IPV6ROUTE:
		return "ipv6route"
	case PROTO_IPV6FRAG:
		return "ipv6frag"
	case PROTO_IDRP:
		return "idrp"
	case PROTO_RSVP:
		return "rsvp"
	case PROTO_GRE:
		return "gre"
	case PROTO_ESP:
		return "esp"
	case PROTO_AH:
		return "ah"
	case PROTO_SKIP:
		return "skip"
	case PROTO_IPV6ICMP:
		return "ipv6icmp"
	case PROTO_IPV6NONXT:
		return "ipv6nonxt"
	case PROTO_IPV6OPTS:
		return "ipv6opts"
	case PROTO_RSPF:
		return "rspf"
	case PROTO_VMTP:
		return "vmtp"
	case PROTO_EIGRP:
		return "eigrp"
	case PROTO_OSPF:
		return "ospf"
	case PROTO_AX25:
		return "ax25"
	case PROTO_IPIP:
		return "ipip"
	case PROTO_ETHERIP:
		return "etherip"
	case PROTO_ENCAP:
		return "encap"
	case PROTO_PIM:
		return "pim"
	case PROTO_IPCOMP:
		return "ipcomp"
	case PROTO_VRRP:
		return "vrrp"
	case PROTO_L2TP:
		return "l2tp"
	case PROTO_ISIS:
		return "isis"
	case PROTO_SCTP:
		return "sctp"
	case PROTO_FC:
		return "fc"
	case PROTO_MOBILITYHEADER:
		return "mobilityheader"
	case PROTO_UDPLITE:
		return "udplite"
	case PROTO_MPLSINIP:
		return "mplsinip"
	case PROTO_MANET:
		return "manet"
	case PROTO_HIP:
		return "hip"
	case PROTO_SHIM6:
		return "shim6"
	case PROTO_WESP:
		return "wesp"
	case PROTO_ROHC:
		return "rohc"
	}
	panic("This shouldn't happened")
	return "unknown"
}

func (ipport IPPort) String() string {
	protocolSuffix := ""
	if ipport.Protocol != nil {
		protocolSuffix = "/" + (*ipport.Protocol).String()
		if protocolSuffix == "/ip" {
			protocolSuffix = ""
		}
	}

	if ipport.Port == nil {
		return ipport.IP.String() + protocolSuffix
	}

	return ipport.IP.String() + ":" + strconv.Itoa(int(*ipport.Port)) + protocolSuffix
}

// awk 'BEGIN{prevId=-1} {if($1 == "#" || $1 == "" || $2 <= prevId){next} gsub("[-.]", "", $1) ;printf "%s", "PROTO_"toupper($1)" = Protocol("$2") // "; $1=""; prevId=$2; $2=""; print $0}' < /etc/protocols

const (
	PROTO_IP             = Protocol(0)   // IP # internet protocol, pseudo protocol number
	PROTO_ICMP           = Protocol(1)   // ICMP # internet control message protocol
	PROTO_IGMP           = Protocol(2)   // IGMP # Internet Group Management
	PROTO_GGP            = Protocol(3)   // GGP # gateway-gateway protocol
	PROTO_IPENCAP        = Protocol(4)   // IP-ENCAP # IP encapsulated in IP (officially ``IP'')
	PROTO_ST             = Protocol(5)   // ST # ST datagram mode
	PROTO_TCP            = Protocol(6)   // TCP # transmission control protocol
	PROTO_EGP            = Protocol(8)   // EGP # exterior gateway protocol
	PROTO_IGP            = Protocol(9)   // IGP # any private interior gateway (Cisco)
	PROTO_PUP            = Protocol(12)  // PUP # PARC universal packet protocol
	PROTO_UDP            = Protocol(17)  // UDP # user datagram protocol
	PROTO_HMP            = Protocol(20)  // HMP # host monitoring protocol
	PROTO_XNSIDP         = Protocol(22)  // XNS-IDP # Xerox NS IDP
	PROTO_RDP            = Protocol(27)  // RDP # "reliable datagram" protocol
	PROTO_ISOTP4         = Protocol(29)  // ISO-TP4 # ISO Transport Protocol class 4 [RFC905]
	PROTO_DCCP           = Protocol(33)  // DCCP # Datagram Congestion Control Prot. [RFC4340]
	PROTO_XTP            = Protocol(36)  // XTP # Xpress Transfer Protocol
	PROTO_DDP            = Protocol(37)  // DDP # Datagram Delivery Protocol
	PROTO_IDPRCMTP       = Protocol(38)  // IDPR-CMTP # IDPR Control Message Transport
	PROTO_IPV6           = Protocol(41)  // IPv6 # Internet Protocol, version 6
	PROTO_IPV6ROUTE      = Protocol(43)  // IPv6-Route # Routing Header for IPv6
	PROTO_IPV6FRAG       = Protocol(44)  // IPv6-Frag # Fragment Header for IPv6
	PROTO_IDRP           = Protocol(45)  // IDRP # Inter-Domain Routing Protocol
	PROTO_RSVP           = Protocol(46)  // RSVP # Reservation Protocol
	PROTO_GRE            = Protocol(47)  // GRE # General Routing Encapsulation
	PROTO_ESP            = Protocol(50)  // IPSEC-ESP # Encap Security Payload [RFC2406]
	PROTO_AH             = Protocol(51)  // IPSEC-AH # Authentication Header [RFC2402]
	PROTO_SKIP           = Protocol(57)  // SKIP # SKIP
	PROTO_IPV6ICMP       = Protocol(58)  // IPv6-ICMP # ICMP for IPv6
	PROTO_IPV6NONXT      = Protocol(59)  // IPv6-NoNxt # No Next Header for IPv6
	PROTO_IPV6OPTS       = Protocol(60)  // IPv6-Opts # Destination Options for IPv6
	PROTO_RSPF           = Protocol(73)  // RSPF CPHB # Radio Shortest Path First (officially CPHB)
	PROTO_VMTP           = Protocol(81)  // VMTP # Versatile Message Transport
	PROTO_EIGRP          = Protocol(88)  // EIGRP # Enhanced Interior Routing Protocol (Cisco)
	PROTO_OSPF           = Protocol(89)  // OSPFIGP # Open Shortest Path First IGP
	PROTO_AX25           = Protocol(93)  // AX.25 # AX.25 frames
	PROTO_IPIP           = Protocol(94)  // IPIP # IP-within-IP Encapsulation Protocol
	PROTO_ETHERIP        = Protocol(97)  // ETHERIP # Ethernet-within-IP Encapsulation [RFC3378]
	PROTO_ENCAP          = Protocol(98)  // ENCAP # Yet Another IP encapsulation [RFC1241]
	PROTO_PIM            = Protocol(103) // PIM # Protocol Independent Multicast
	PROTO_IPCOMP         = Protocol(108) // IPCOMP # IP Payload Compression Protocol
	PROTO_VRRP           = Protocol(112) // VRRP # Virtual Router Redundancy Protocol [RFC5798]
	PROTO_L2TP           = Protocol(115) // L2TP # Layer Two Tunneling Protocol [RFC2661]
	PROTO_ISIS           = Protocol(124) // ISIS # IS-IS over IPv4
	PROTO_SCTP           = Protocol(132) // SCTP # Stream Control Transmission Protocol
	PROTO_FC             = Protocol(133) // FC # Fibre Channel
	PROTO_MOBILITYHEADER = Protocol(135) // Mobility-Header # Mobility Support for IPv6 [RFC3775]
	PROTO_UDPLITE        = Protocol(136) // UDPLite # UDP-Lite [RFC3828]
	PROTO_MPLSINIP       = Protocol(137) // MPLS-in-IP # MPLS-in-IP [RFC4023]
	PROTO_MANET          = Protocol(138) // # MANET Protocols [RFC5498]
	PROTO_HIP            = Protocol(139) // HIP # Host Identity Protocol
	PROTO_SHIM6          = Protocol(140) // Shim6 # Shim6 Protocol [RFC5533]
	PROTO_WESP           = Protocol(141) // WESP # Wrapped Encapsulating Security Payload
	PROTO_ROHC           = Protocol(142) // ROHC # Robust Header Compression
)
