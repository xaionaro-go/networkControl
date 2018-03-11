package linuxHost

import (
	"errors"
	"fmt"
	"github.com/vishvananda/netlink"
	"github.com/xaionaro-go/iscDhcp"
	"github.com/xaionaro-go/netTree"
	"github.com/xaionaro-go/networkControl"
	"github.com/xaionaro-go/networkControl/firewalls/iptables"
	"net"
	"os"
	"os/exec"
	"strings"
)

var (
	errNotImplemented = errors.New("not implemented (yet?)")
)

const (
	DHCP_CONFIG_PATH = "/etc/dhcp/dhcpd.conf"
)

type AccessDetails struct {
	Host string
	Post int
	// ...
}

type linuxHost struct {
	networkControl.HostBase
	accessDetails *AccessDetails
	dhcpd         *iscDhcp.DHCP
}

func NewHost(accessDetails *AccessDetails) networkControl.HostI {
	host := linuxHost{}
	err := host.HostBase.SetParent(&host)
	if err != nil {
		panic(err)
	}
	if accessDetails != nil {
		panic(errNotImplemented)
		accessDetailsCopy := *accessDetails
		host.accessDetails = &accessDetailsCopy
	}
	host.HostBase.SetFirewall(iptables.NewFirewall())
	host.dhcpd = iscDhcp.NewDHCP()
	return &host
}

func (host *linuxHost) SetFirewall(newFirewall networkControl.FirewallI) error {
	return errNotImplemented
}

func (host *linuxHost) ApplyDiff(stateDiff networkControl.StateDiff) error {
	return errNotImplemented
}
func (host *linuxHost) InquireDHCP() (dhcp networkControl.DHCP) {
	// Scanning on the local machine only, so "accessDetails" is not supported, yet
	if host.accessDetails != nil {
		panic(errNotImplemented)
	}

	err := host.dhcpd.ReloadConfig()
	if err != nil {
		panic(err)
	}
	return networkControl.DHCP(host.dhcpd.Config.Root)
}
func (host *linuxHost) InquireBridgedVLANs() networkControl.VLANs {
	// Scanning on the local machine only, so "accessDetails" is not supported, yet
	if host.accessDetails != nil {
		panic(errNotImplemented)
	}

	return host.inquireBridgedVLANs(netTree.GetTree().ToSlice())
}
func (host *linuxHost) inquireBridgedVLANs(ifaces netTree.Nodes) networkControl.VLANs { // TODO: consider possibility of .1q in .1q
	vlans := networkControl.VLANs{}

	for _, iface := range ifaces {
		link, ok := iface.Link.(*netlink.Vlan)
		if !ok {
			continue
		}

		if len(iface.Children) != 1 {
			// TODO: consider this case (not-bridged vlan iface)
			continue
		}
		child := iface.Children[0]
		childLink, ok := child.Link.(*netlink.Bridge)
		if !ok {
			// TODO: consider this case (not-bridged vlan iface)
			continue
		}

		// IP-addresses
		ips := networkControl.IPNets{}
		addrs, err := netlink.AddrList(childLink, netlink.FAMILY_V4)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Got an error from netlink.AddrList(link<%v>, netlink.FAMILY_V4): %v", childLink.LinkAttrs.Name, err.Error())
			//panic(err)
		}
		for _, addr := range addrs {
			ips = append(ips, networkControl.IPNet(*addr.Peer))
		}

		// Security-level
		securityLevel := host.GetFirewall().InquireSecurityLevel(childLink.Name)

		vlans[link.VlanId] = &networkControl.VLAN{
			Interface: net.Interface{
				Name: childLink.Name,
				MTU:  childLink.MTU,
			},
			VlanId:        link.VlanId,
			IPs:           ips,
			SecurityLevel: securityLevel,
		}
	}

	return vlans
}

func (host *linuxHost) InquireACLs() networkControl.ACLs {
	return host.GetFirewall().InquireACLs()
}

func (host *linuxHost) InquireSNATs() networkControl.SNATs {
	return host.GetFirewall().InquireSNATs()
}

func (host *linuxHost) InquireDNATs() networkControl.DNATs {
	return host.GetFirewall().InquireDNATs()
}

func parseIPNet(words []string) (networkControl.IPNet, []string) {
	if words[0] == "default" {
		return networkControl.IPNet{IP: net.ParseIP("0.0.0.0"), Mask: net.IPv4Mask(0, 0, 0, 0)}, words[1:]
	}
	ipnet, err := networkControl.IPNetFromCIDRString(words[0])
	if err != nil {
		panic(err)
	}
	return ipnet, words[1:]
}
func parseIP(words []string) (ip net.IP, newWords []string) {
	ip = net.ParseIP(words[1])
	newWords = words[1:]
	return
}

func (host *linuxHost) InquireRoutes() (result networkControl.Routes) {
	outB, err := exec.Command("ip route show table fwsm").Output()
	if err != nil {
		panic(err)
	}
	out := string(outB)
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		words := strings.Split(line, " ")
		var route networkControl.Route

		route.Destination, words = parseIPNet(words)

		for len(words) > 0 {
			switch words[0] {
			case "via":
				route.Gateway, words = parseIP(words[1:])
			case "dev":
				route.IfName = words[1]
				words = words[2:]
			case "proto", "kernel", "scope", "link":
				words = words[1:]
			case "src":
				words = words[2:]
			case "from":
				var source networkControl.IPNet
				source, words = parseIPNet(words[1:])
				route.Sources = append(route.Sources, source)
			default:
				panic("unknown word: \""+words[0]+"\"")
			}
		}
		if len(route.Sources) == 0 {
			route.Sources = networkControl.IPNets{networkControl.IPNet{IP: net.ParseIP("0.0.0.0"), Mask: net.IPv4Mask(0, 0, 0, 0)}}
		}

		result = append(result, &route)
	}

	return
}

func (host *linuxHost) RescanState() error {
	host.States.Cur.BridgedVLANs = host.InquireBridgedVLANs()
	host.States.Cur.DHCP = host.InquireDHCP()
	host.States.Cur.ACLs = host.InquireACLs()
	host.States.Cur.SNATs = host.InquireSNATs()
	host.States.Cur.DNATs = host.InquireDNATs()
	host.States.Cur.Routes = host.InquireRoutes()

	return errNotImplemented
}
func (host *linuxHost) SetDHCPState(state networkControl.State) error {
	return errNotImplemented
}
func (host *linuxHost) SaveToDisk() (err error) { // ATM, works only with Debian with preinstalled packages: "iptables" and "ipset"!
	host.SetDHCPState(host.States.Cur)
	err = host.dhcpd.SaveConfig()
	if err != nil {
		return err
	}

	// iptables


	// ipset

	return errNotImplemented
}
func (host *linuxHost) RestoreFromDisk() error { // ATM, works only with Debian with preinstalled packages: "iptables" and "ipset"!
	return errNotImplemented
}
