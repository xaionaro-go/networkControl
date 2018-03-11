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
	"strconv"
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
	netlink       *netlink.Handle
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
	host.netlink, err = netlink.NewHandle()
	if err != nil {
		panic(err)
	}
	return &host
}

func (host *linuxHost) SetFirewall(newFirewall networkControl.FirewallI) error {
	return errNotImplemented
}

func (host *linuxHost) getTrunkLink() (netlink.Link, error) {
	return host.netlink.LinkByName("trunk")
}

func (host *linuxHost) AddVLAN(vlan networkControl.VLAN) error {
	if host.accessDetails != nil {
		panic(errNotImplemented)
	}

	trunk, err := host.getTrunkLink()
	if err != nil {
		return err
	}

	bridgeLink := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: vlan.Name}}
	if err := host.netlink.LinkAdd(bridgeLink); err != nil {
		return err
	}

	if err := host.netlink.LinkSetUp(bridgeLink); err != nil {
		return err
	}

	vlanLink := &netlink.Vlan{netlink.LinkAttrs{Name: "trunk."+strconv.Itoa(vlan.VlanId), ParentIndex: trunk.Attrs().Index}, vlan.VlanId}
	if err := host.netlink.LinkAdd(vlanLink); err != nil {
		return err
	}

	if err := host.netlink.LinkSetMaster(vlanLink, bridgeLink); err != nil {
		return err
	}

	return nil
}

func (host *linuxHost) AddACL(acl networkControl.ACL) error {
	return host.GetFirewall().AddACL(acl)
}

func (host *linuxHost) AddSNAT(snat networkControl.SNAT) error {
	return host.GetFirewall().AddSNAT(snat)
}

func (host *linuxHost) AddDNAT(dnat networkControl.DNAT) error {
	return host.GetFirewall().AddDNAT(dnat)
}

func (host *linuxHost) AddRoute(route networkControl.Route) error {
	if len(route.Sources) != 1 {
		panic(fmt.Sprintf("Not implemented, yet: %v", route))
	}
	source := route.Sources[0]
	if source.IP.String() != "0.0.0.0" {
		panic(fmt.Sprintf("Not implemented, yet: %v", route))
	}

	_, err := exec.Command(fmt.Sprintf("ip route add %v via %v metric %v table fwsm", route.Destination, route.Gateway, route.Metric)).Output()
	if err != nil {
		return err
	}

	return nil
}

func (host *linuxHost) UpdateVLAN(vlan networkControl.VLAN) error {
	return errNotImplemented
}

func (host *linuxHost) UpdateACL(acl networkControl.ACL) error {
	return host.GetFirewall().UpdateACL(acl)
}

func (host *linuxHost) UpdateSNAT(snat networkControl.SNAT) error {
	return host.GetFirewall().UpdateSNAT(snat)
}

func (host *linuxHost) UpdateDNAT(dnat networkControl.DNAT) error {
	return host.GetFirewall().UpdateDNAT(dnat)
}

func (host *linuxHost) UpdateRoute(route networkControl.Route) error {
	return errNotImplemented
}


func (host *linuxHost) RemoveVLAN(vlan networkControl.VLAN) error {
	if host.accessDetails != nil {
		panic(errNotImplemented)
	}

	vlanLink, err := host.netlink.LinkByName("trunk."+strconv.Itoa(vlan.VlanId))
	if err != nil {
		return err
	}

	bridgeLink, err := host.netlink.LinkByName(vlan.Name)
	if err != nil {
		return err
	}

	err = host.netlink.LinkDel(vlanLink)
	if err != nil {
		return err
	}

	host.netlink.LinkSetDown(bridgeLink)
	err = host.netlink.LinkDel(bridgeLink)
	if err != nil {
		return err
	}

	return nil
}

func (host *linuxHost) RemoveACL(acl networkControl.ACL) error {
	return host.GetFirewall().RemoveACL(acl)
}

func (host *linuxHost) RemoveSNAT(snat networkControl.SNAT) error {
	return host.GetFirewall().RemoveSNAT(snat)
}

func (host *linuxHost) RemoveDNAT(dnat networkControl.DNAT) error {
	return host.GetFirewall().RemoveDNAT(dnat)
}

func (host *linuxHost) RemoveRoute(route networkControl.Route) error {
	if len(route.Sources) != 1 {
		panic(fmt.Sprintf("Not implemented, yet: %v", route))
	}
	source := route.Sources[0]
	if source.IP.String() != "0.0.0.0" {
		panic(fmt.Sprintf("Not implemented, yet: %v", route))
	}

	_, err := exec.Command(fmt.Sprintf("ip route del %v via %v metric %v table fwsm", route.Destination, route.Gateway, route.Metric)).Output()
	if err != nil {
		return err
	}

	return nil
}

func (host *linuxHost) ApplyDiff(stateDiff networkControl.StateDiff) error {
	for _, vlan := range stateDiff.Added.BridgedVLANs {
		err := host.AddVLAN(*vlan)
		if err != nil {
			return err
		}
	}
	for _, acl := range stateDiff.Added.ACLs {
		err := host.AddACL(*acl)
		if err != nil {
			return err
		}
	}
	for _, snat := range stateDiff.Added.SNATs {
		err := host.AddSNAT(*snat)
		if err != nil {
			return err
		}
	}
	for _, dnat := range stateDiff.Added.DNATs {
		err := host.AddDNAT(*dnat)
		if err != nil {
			return err
		}
	}
	for _, route := range stateDiff.Added.Routes {
		err := host.AddRoute(*route)
		if err != nil {
			return err
		}
	}

	var err error

	// Running the new state on DHCP
	oldDHCPState := networkControl.DHCP(host.dhcpd.Config.Root)
	host.SetDHCPState(stateDiff.Updated.DHCP)
	err = host.dhcpd.Restart()
	if err != nil {
		return err
	}

	// But we need to revert the old state on the disk (the new state shouldn't be saved on the disk, yet)
	host.SetDHCPState(oldDHCPState)
	err = host.dhcpd.SaveConfig()
	if err != nil {
		return err
	}
	// And the running state should be new in our information
	host.SetDHCPState(stateDiff.Updated.DHCP)

	for _, vlan := range stateDiff.Updated.BridgedVLANs {
		err := host.UpdateVLAN(*vlan)
		if err != nil {
			return err
		}
	}
	for _, acl := range stateDiff.Updated.ACLs {
		err := host.UpdateACL(*acl)
		if err != nil {
			return err
		}
	}
	for _, snat := range stateDiff.Updated.SNATs {
		err := host.UpdateSNAT(*snat)
		if err != nil {
			return err
		}
	}
	for _, dnat := range stateDiff.Updated.DNATs {
		err := host.UpdateDNAT(*dnat)
		if err != nil {
			return err
		}
	}
	for _, route := range stateDiff.Updated.Routes {
		err := host.UpdateRoute(*route)
		if err != nil {
			return err
		}
	}

	for _, vlan := range stateDiff.Removed.BridgedVLANs {
		err := host.RemoveVLAN(*vlan)
		if err != nil {
			return err
		}
	}
	for _, acl := range stateDiff.Removed.ACLs {
		err := host.RemoveACL(*acl)
		if err != nil {
			return err
		}
	}
	for _, snat := range stateDiff.Removed.SNATs {
		err := host.RemoveSNAT(*snat)
		if err != nil {
			return err
		}
	}
	for _, dnat := range stateDiff.Removed.DNATs {
		err := host.RemoveDNAT(*dnat)
		if err != nil {
			return err
		}
	}
	for _, route := range stateDiff.Removed.Routes {
		err := host.RemoveRoute(*route)
		if err != nil {
			return err
		}
	}

	return nil
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
		addrs, err := host.netlink.AddrList(childLink, netlink.FAMILY_V4)
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
func (host *linuxHost) SetDHCPState(state networkControl.DHCP) error {
	return errNotImplemented
}
func (host *linuxHost) SaveToDisk() (err error) { // ATM, works only with Debian with preinstalled packages: "iptables" and "ipset"!

	// vlans

	// routes

	// dhcp

	host.SetDHCPState(host.States.Cur.DHCP)
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
