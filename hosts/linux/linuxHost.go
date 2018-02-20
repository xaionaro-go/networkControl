package linuxHost

import (
	"errors"
	"fmt"
	"github.com/vishvananda/netlink"
	"github.com/xaionaro-go/netTree"
	"github.com/xaionaro-go/networkControl"
	"github.com/xaionaro-go/networkControl/firewalls/iptables"
	"net"
	"os"
)

var (
	errNotImplemented = errors.New("not implemented, yet")
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
func (host *linuxHost) scanBridgedVLANs(ifaces netTree.Nodes) networkControl.VLANs { // TODO: consider possibility of .1q in .1q
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
	if host.accessDetails != nil {
		panic(errNotImplemented)
	}
	ifaces := netTree.GetTree().ToSlice() // Scanning on the local machine only, so "accessDetails" is not supported, yet

	host.States.Cur.BridgedVLANs = host.scanBridgedVLANs(ifaces)

	return errNotImplemented
}
func (host *linuxHost) SaveToDisk() error { // ATM, works only with Debian with preinstalled packages: "iptables" and "ipset"!
	return errNotImplemented
}
func (host *linuxHost) RestoreFromDisk() error { // ATM, works only with Debian with preinstalled packages: "iptables" and "ipset"!
	return errNotImplemented
}
