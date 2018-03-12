package linuxHost

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vishvananda/netlink"
	"github.com/xaionaro-go/iscDhcp"
	"github.com/xaionaro-go/iscDhcp/cfg"
	"github.com/xaionaro-go/netTree"
	"github.com/xaionaro-go/networkControl"
	"github.com/xaionaro-go/networkControl/firewalls/iptables"
	"io/ioutil"
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

	vlanLink := &netlink.Vlan{netlink.LinkAttrs{Name: "trunk." + strconv.Itoa(vlan.VlanId), ParentIndex: trunk.Attrs().Index}, vlan.VlanId}
	if err := host.netlink.LinkAdd(vlanLink); err != nil {
		return err
	}

	if err := host.netlink.LinkSetMaster(vlanLink, bridgeLink); err != nil {
		return err
	}

	err = host.GetFirewall().SetSecurityLevel(vlan.Name, vlan.SecurityLevel)
	if err != nil {
		return err
	}

	for _, ip := range vlan.IPs {
		addr, err := netlink.ParseAddr(ip.String())
		if err != nil {
			return err
		}
		err = host.netlink.AddrAdd(bridgeLink, addr)
		if err != nil {
			return err
		}
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

	// Getting current configuration

	oldVlan := host.InquireBridgedVLAN(vlan.VlanId)
	if oldVlan == nil {
		panic(fmt.Errorf("oldVlan == nil: %v", vlan))
	}
	if oldVlan.Name != vlan.Name {
		return errNotImplemented
	}

	// Fixeding the security level

	if oldVlan.SecurityLevel != vlan.SecurityLevel {
		err := host.GetFirewall().SetSecurityLevel(vlan.Name, vlan.SecurityLevel)
		if err != nil {
			return err
		}
	}

	// Checking for added and removed IP addresses

	addIPs := networkControl.IPNets{}
	remIPs := networkControl.IPNets{}

	oldIPsMap := map[string]*networkControl.IPNet{}
	for idx, ip := range oldVlan.IPs {
		oldIPsMap[ip.String()] = &oldVlan.IPs[idx]
	}

	newIPsMap := map[string]*networkControl.IPNet{}
	for idx, ip := range vlan.IPs {
		newIPsMap[ip.String()] = &vlan.IPs[idx]
		if oldIPsMap[ip.String()] != nil {
			continue
		}
		addIPs = append(addIPs, ip)
	}

	for _, ip := range oldVlan.IPs {
		if newIPsMap[ip.String()] != nil {
			continue
		}
		remIPs = append(remIPs, ip)
	}

	// Getting netlink pointers

	bridgeLink, err := host.netlink.LinkByName(vlan.Name)
	if err != nil {
		return err
	}
	curAddrs, err := host.netlink.AddrList(bridgeLink, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	curAddrMap := map[string]*netlink.Addr{}
	for idx, addr := range curAddrs {
		addrString := strings.Split(addr.String(), " ")[0]
		curAddrMap[addrString] = &curAddrs[idx]
	}

	// Adding and removing IP addresses

	for _, ip := range remIPs {
		addr := curAddrMap[ip.String()]
		if addr == nil {
			panic(fmt.Errorf("This shouldn't happened: %v", ip))
		}

		err := host.netlink.AddrDel(bridgeLink, addr)
		if err != nil {
			return err
		}
	}

	for _, ip := range addIPs {
		addr, err := netlink.ParseAddr(ip.String())
		if err != nil {
			return err
		}

		err = host.netlink.AddrAdd(bridgeLink, addr)
		if err != nil {
			return err
		}
	}

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

	vlanLink, err := host.netlink.LinkByName("trunk." + strconv.Itoa(vlan.VlanId))
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

	panic("errNotImplemented") // TODO: clean up security levels chain in iptables

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

	// Adding

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

	// Updating

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

	// Removing

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
func (host *linuxHost) InquireBridgedVLAN(vlanId int) *networkControl.VLAN {
	vlans := host.InquireBridgedVLANs()

	for _, vlan := range vlans {
		if vlan.VlanId != vlanId {
			continue
		}

		return vlan
	}

	return nil
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
	outB, err := exec.Command("ip", "route", "show", "table", "fwsm").Output()
	if err != nil {
		panic(err)
	}
	out := string(outB)
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

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
				panic("unknown word: \"" + words[0] + "\"")
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

	return nil
}
func (host *linuxHost) SetDHCPState(state networkControl.DHCP) error {
	host.dhcpd.Config.Root = cfg.Root(state)
	return nil
}

type netConfigT struct {
	VLANs  networkControl.VLANs
	Routes networkControl.Routes
}

func (host *linuxHost) SaveToDisk() (err error) { // ATM, works only with Debian with preinstalled packages: "iptables" and "ipset"!

	// vlans and routes

	{
		netConfig := netConfigT{}
		netConfig.VLANs  = host.States.Cur.BridgedVLANs
		netConfig.Routes = host.States.Cur.Routes
		netConfigJson, _ := json.Marshal(netConfig)
		err = ioutil.WriteFile("/etc/fwsm-net.json", netConfigJson, 0644)
		if err != nil {
			return err
		}
	}

	// dhcp

	host.SetDHCPState(host.States.Cur.DHCP)
	err = host.dhcpd.SaveConfig()
	if err != nil {
		return err
	}

	// iptables

	_, err = exec.Command("sh", "-c", "iptables-save > /etc/iptables/fwsm.rules").Output()
	if err != nil {
		return err
	}

	// ipset

	_, err = exec.Command("ipset", "save", "-file", "/etc/ipset-fwsm.dump").Output()
	if err != nil {
		return err
	}

	// finish

	return nil
}
func (host *linuxHost) RestoreFromDisk() error { // ATM, works only with Debian with preinstalled packages: "iptables" and "ipset"!

	// vlans and routes

	if _, err := os.Stat("/etc/fwsm-net.json"); err == nil {
		plan, err := ioutil.ReadFile("/etc/fwsm-net.json")
		if err != nil {
			return err
		}
		netConfig := netConfigT{}
		err = json.Unmarshal(plan, &netConfig)
		if err != nil {
			return err
		}
		host.States.New.BridgedVLANs = netConfig.VLANs
		host.States.New.Routes       = netConfig.Routes
		err = host.Apply()
		if err != nil {
			return err
		}
	}

	// ipset

	if _, err := os.Stat("/etc/ipset-fwsm.dump"); err == nil {
		_, err := exec.Command("ipset", "restore", "-file", "/etc/ipset-fwsm.dump").Output()
		if err != nil {
			return err
		}
	}

	// dhcp

	host.SetDHCPState(host.States.Cur.DHCP)
	err := host.dhcpd.SaveConfig()
	if err != nil {
		return err
	}

	// iptables

	if _, err := os.Stat("/etc/ipset-fwsm.dump"); err == nil {
		_, err := exec.Command("iptables-restore", "/etc/ipset-fwsm.dump").Output()
		if err != nil {
			return err
		}
	}

	// finish

	return host.RescanState()
}
