package linuxHost

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/vishvananda/netlink"
	"github.com/xaionaro-go/isccfg"
	"github.com/xaionaro-go/netTree"
	"github.com/xaionaro-go/networkControl"
	"github.com/xaionaro-go/networkControl/firewalls/iptables"
	"net"
	"os"
)

var (
	errNotImplemented = errors.New("not implemented, yet")
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
	return &host
}

func (host *linuxHost) SetFirewall(newFirewall networkControl.FirewallI) error {
	return errNotImplemented
}

func (host *linuxHost) ApplyDiff(stateDiff networkControl.StateDiff) error {
	return errNotImplemented
}
func (host *linuxHost) InquireDHCP() (common networkControl.DHCPCommon, subnets networkControl.DHCPs) {
	// Scanning on the local machine only, so "accessDetails" is not supported, yet
	if host.accessDetails != nil {
		panic(errNotImplemented)
	}

	cfgFile, err := os.Open(DHCP_CONFIG_PATH)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Got an error from os.Open(\"%v\"): %v", DHCP_CONFIG_PATH, err.Error())
	}
	defer cfgFile.Close()

	cfgReader := bufio.NewReader(cfgFile)

	cfg, err := isccfg.Parse(cfgReader)

	return
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
func (host *linuxHost) RescanState() error {
	host.States.Cur.DHCP, host.States.Cur.DHCPs = host.InquireDHCP()
	host.States.Cur.BridgedVLANs = host.InquireBridgedVLANs()
	host.States.Cur.ACLs         = host.InquireACLs()
	host.States.Cur.SNATs        = host.InquireSNATs()
	host.States.Cur.DNATs        = host.InquireDNATs()
	host.States.Cur.Routes       = host.InquireRoutes()

	return errNotImplemented
}
func (host *linuxHost) SaveToDisk() error { // ATM, works only with Debian with preinstalled packages: "iptables" and "ipset"!
	return errNotImplemented
}
func (host *linuxHost) RestoreFromDisk() error { // ATM, works only with Debian with preinstalled packages: "iptables" and "ipset"!
	return errNotImplemented
}
