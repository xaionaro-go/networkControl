package linuxHost

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vishvananda/netlink"
	"github.com/xaionaro-go/iscDhcp"
	"github.com/xaionaro-go/iscDhcp/cfg"
	"github.com/xaionaro-go/netTree"
	"github.com/xaionaro-go/networkControl"
	"github.com/xaionaro-go/networkControl/firewalls/iptables"
	"hash/crc32"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

var (
	errNotImplemented = errors.New("not implemented (yet?)")
	errIfNameCollision = errors.New("Got a collision of backend interface names. It's an internal error caused by a limit in 15 characters for linux network interface names. You can change crc32q value in linuxHost.go to bypass the problem.")
	errUnknownIfName = errors.New("Unknown interface in the backend. Cannot convert back to the real interface name")
)

const (
	DHCP_CONFIG_PATH      = "/etc/dhcp/dhcpd.conf"
	SCRIPTS_PATH          = "/root/fwsm-config/linux"
	NETCONTOL_CONFIG_PATH = "/etc/networkControl.json"
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
	crc32q        *crc32.Table
	ifNameMap     map[string]string
}


func (host *linuxHost) IfNameToLinuxIfName(ifName string) string {
	if len(ifName) < 15 {
		return ifName
	}

	beginning := ifName[:6]
	endingBinary := crc32.Checksum([]byte(ifName), host.crc32q)
	hostIfName := fmt.Sprintf("%v%08x", beginning, endingBinary)
	if host.ifNameMap[hostIfName] != "" && host.ifNameMap[hostIfName] != ifName {
		panic(errIfNameCollision)
	}
	host.ifNameMap[hostIfName] = ifName
	return hostIfName
}
func (host *linuxHost) IfNameToHostIfName(ifName string) string {
	return host.IfNameToLinuxIfName(ifName)
}
func (host linuxHost) LinuxIfNameToIfName(hostIfName string) string {
	if len(hostIfName) < 15 {
		return hostIfName
	}
	result := host.ifNameMap[hostIfName]
	if result != "" {
		host.Warningf("Cannot find the real name for interface %v", hostIfName)
		return hostIfName
	}
	return result
}
func (host linuxHost) HostIfNameToIfName(hostIfName string) string {
	return host.LinuxIfNameToIfName(hostIfName)
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
	host.crc32q = crc32.MakeTable(0xD5828281)
	host.ifNameMap = map[string]string{}
	host.HostBase.SetFirewall(iptables.NewFirewall(&host))
	host.dhcpd = iscDhcp.NewDHCP()
	host.netlink, err = netlink.NewHandle()
	if err != nil {
		panic(err)
	}

	host.exec("ip", "rule", "del", "from", "any", "lookup", "fwsm")
	err = host.exec("ip", "rule", "add", "from", "any", "lookup", "fwsm")
	if err != nil {
		panic(err)
	}

	return &host
}

func (host *linuxHost) SetFirewall(newFirewall networkControl.FirewallI) error {
	panic(errNotImplemented)
	return errNotImplemented
}

func (host *linuxHost) getTrunkLink() (netlink.Link, error) {
	return host.netlink.LinkByName("trunk")
}

func (host *linuxHost) AddVLAN(vlan networkControl.VLAN) error {
	if vlan.IsIgnored {
		return nil
	}

	if host.accessDetails != nil {
		panic(errNotImplemented)
	}
	host.Debugf("AddVLAN: %v", vlan)

	trunk, err := host.getTrunkLink()
	if err != nil {
		host.LogError(err)
		return err
	}

	bridgeLink := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: host.IfNameToHostIfName(vlan.Name)}}
	if err := host.netlink.LinkAdd(bridgeLink); err != nil {
		if err.Error() == "file exists" {
			host.LogWarning(err, vlan, bridgeLink)
		} else {
			host.LogError(err)
			return err
		}
	}

	if err := host.netlink.LinkSetUp(bridgeLink); err != nil {
		host.LogError(err)
		return err
	}

	vlanLink := &netlink.Vlan{netlink.LinkAttrs{Name: "trunk." + strconv.Itoa(vlan.VlanId), ParentIndex: trunk.Attrs().Index}, vlan.VlanId}
	if err := host.netlink.LinkAdd(vlanLink); err != nil {
		if err.Error() == "file exists" {
			host.LogWarning(err, vlan, vlanLink)
		} else {
			host.LogError(err)
			return err
		}
	}

	if err := host.netlink.LinkSetMaster(vlanLink, bridgeLink); err != nil {
		host.LogError(err)
		return err
	}

	err = host.GetFirewall().SetSecurityLevel(host.IfNameToHostIfName(vlan.Name), vlan.SecurityLevel)
	if err != nil {
		host.LogError(err)
		return err
	}

	for _, ip := range vlan.IPs {
		addr, err := netlink.ParseAddr(ip.String())
		if err != nil {
			host.LogError(err)
			return err
		}
		err = host.netlink.AddrAdd(bridgeLink, addr)
		if err != nil {
			if err.Error() == "file exists" {
				host.LogWarning(err, ip, addr)
			} else {
				host.LogError(err)
				return err
			}
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

func (host *linuxHost) exec(command ...interface{}) error {
	host.Infof("linuxHost.exec(%v)", command)

	commandStr := []string{}
	for _, word := range command {
		commandStr = append(commandStr, fmt.Sprintf("%v", word))
	}

	cmd := exec.Command(commandStr[0], commandStr[1:]...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		err = fmt.Errorf("Got an error while execution of %v: %v\nstdout: %v\nstderr: %v", commandStr, err, out.String(), stderr.String())
		host.Errorf("%v", err.Error())
		return err
	}

	return nil
}

func (host *linuxHost) AddRoute(route networkControl.Route) error {
	if len(route.Sources) != 1 {
		panic(fmt.Sprintf("Not implemented, yet: %v", route))
	}
	source := route.Sources[0]
	if source.IP.String() != "0.0.0.0" {
		panic(fmt.Sprintf("Not implemented, yet: %v", route))
	}

	err := host.exec("ip", "route", "add", route.Destination, "via", route.Gateway, "metric", route.Metric, "table", "fwsm")
	if err != nil {
		if strings.Index(err.Error(), "File exists") != -1 {
			host.LogWarning(err)
		} else {
			host.LogError(err)
			return err
		}
	}

	return nil
}

func (host *linuxHost) UpdateVLAN(vlan networkControl.VLAN) error {
	if vlan.IsIgnored {
		return nil
	}

	// Getting current configuration

	oldVlan := host.InquireBridgedVLAN(vlan.VlanId)
	if oldVlan == nil {
		panic(fmt.Errorf("oldVlan == nil: %v", vlan))
	}

	host.Infof("linuxHost.UpdateVLAN(): %v != %v", vlan, *oldVlan)

	if oldVlan.Name != vlan.Name {
		if host.IfNameToLinuxIfName(vlan.Name) == oldVlan.Name {
			host.Infof("Correcting name %v to %v", oldVlan.Name, vlan.Name)
			oldVlan.Name = vlan.Name
		}
	}
	if oldVlan.Name != vlan.Name {
		host.LogError(errNotImplemented, oldVlan.Name, vlan.Name, oldVlan, vlan)
		return errNotImplemented
	}

	// Fixing the security level

	host.Debugf("linuxHost.UpdateVLAN(): %v; SecurityLevel: %v %v", vlan.Name, oldVlan.SecurityLevel, vlan.SecurityLevel)
	if oldVlan.SecurityLevel != vlan.SecurityLevel {
		err := host.GetFirewall().SetSecurityLevel(vlan.Name, vlan.SecurityLevel)
		if err != nil {
			host.LogError(err)
			return err
		}

		// recheck just in case
		newSecurityLevelCheck := host.GetFirewall().InquireSecurityLevel(vlan.Name)
		if newSecurityLevelCheck != vlan.SecurityLevel {
			panic(fmt.Errorf("cannot set new security level: %v", vlan))
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

	bridgeLink, err := host.netlink.LinkByName(host.IfNameToLinuxIfName(vlan.Name))
	if err != nil {
		host.LogError(err)
		return err
	}
	curAddrs, err := host.netlink.AddrList(bridgeLink, netlink.FAMILY_V4)
	if err != nil {
		host.LogError(err)
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
			host.LogError(err)
			return err
		}
	}

	for _, ip := range addIPs {
		addr, err := netlink.ParseAddr(ip.String())
		if err != nil {
			host.LogError(err)
			return err
		}

		err = host.netlink.AddrAdd(bridgeLink, addr)
		if err != nil {
			host.LogError(err)
			return err
		}
	}

	return nil
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
	host.LogError(errNotImplemented, route)
	return errNotImplemented
}

func (host *linuxHost) RemoveVLAN(vlan networkControl.VLAN) error {
	if vlan.IsIgnored {
		return nil
	}

	if host.accessDetails != nil {
		panic(errNotImplemented)
	}

	vlanLink, err := host.netlink.LinkByName("trunk." + strconv.Itoa(vlan.VlanId))
	if err != nil {
		host.LogError(err)
		return err
	}

	bridgeLink, err := host.netlink.LinkByName(vlan.Name)
	if err != nil {
		host.LogError(err)
		return err
	}

	err = host.netlink.LinkDel(vlanLink)
	if err != nil {
		host.LogError(err)
		return err
	}

	host.netlink.LinkSetDown(bridgeLink)
	err = host.netlink.LinkDel(bridgeLink)
	if err != nil {
		host.LogError(err)
		return err
	}

	//panic(errNotImplemented) // TODO: clean up security levels chain in iptables
	host.Warningf("cleaning up of security levels after removing a VLAN is not implemented, yet. VLAN %v: %v", vlan.VlanId, vlan)

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

	err := host.exec("ip", "route", "del", route.Destination, "via", route.Gateway, "metric", route.Metric, "table", "fwsm")
	if err != nil {
		host.LogError(err)
		return err
	}

	return nil
}

func (host *linuxHost) ApplyDiff(stateDiff networkControl.StateDiff) error {

	// Adding

	//host.Infof("ApplyDiff.Added.BridgedVLANs: %v", stateDiff.Added.BridgedVLANs)
	for _, vlan := range stateDiff.Added.BridgedVLANs {
		err := host.AddVLAN(*vlan)
		if err != nil {
			host.LogError(err, *vlan)
			return err
		}
	}
	for _, acl := range stateDiff.Added.ACLs {
		err := host.AddACL(*acl)
		if err != nil {
			host.LogError(err, *acl)
			return err
		}
	}
	for _, snat := range stateDiff.Added.SNATs {
		err := host.AddSNAT(*snat)
		if err != nil {
			host.LogError(err, *snat)
			return err
		}
	}
	for _, dnat := range stateDiff.Added.DNATs {
		err := host.AddDNAT(*dnat)
		if err != nil {
			host.LogError(err, *dnat)
			return err
		}
	}
	for _, route := range stateDiff.Added.Routes {
		err := host.AddRoute(*route)
		if err != nil {
			host.LogError(err, *route)
			return err
		}
	}

	// Updating

	for _, vlan := range stateDiff.Updated.BridgedVLANs {
		err := host.UpdateVLAN(*vlan)
		if err != nil {
			host.LogError(err, *vlan)
			return err
		}
	}
	for _, acl := range stateDiff.Updated.ACLs {
		err := host.UpdateACL(*acl)
		if err != nil {
			host.LogError(err, *acl)
			return err
		}
	}
	for _, snat := range stateDiff.Updated.SNATs {
		err := host.UpdateSNAT(*snat)
		if err != nil {
			host.LogError(err, *snat)
			return err
		}
	}
	for _, dnat := range stateDiff.Updated.DNATs {
		err := host.UpdateDNAT(*dnat)
		if err != nil {
			host.LogError(err, *dnat)
			return err
		}
	}
	for _, route := range stateDiff.Updated.Routes {
		err := host.UpdateRoute(*route)
		if err != nil {
			host.LogError(err, *route)
			return err
		}
	}

	var err error

	// Running the new state on DHCP
	//oldDHCPState := networkControl.DHCP(host.dhcpd.Config.Root)
	host.SetDHCPState(stateDiff.Updated.DHCP)
	err = host.dhcpd.Restart()
	if err != nil {
		host.LogWarning(err)
	}

	/*
	// But we need to revert the old state on the disk (the new state shouldn't be saved on the disk, yet)
	host.SetDHCPState(oldDHCPState)
	err = host.dhcpd.SaveConfig()
	if err != nil {
		host.LogError(err)
		return err
	}
	// And the running state should be new in our information
	host.SetDHCPState(stateDiff.Updated.DHCP)
	*/

	// Removing

	for _, vlan := range stateDiff.Removed.BridgedVLANs {
		err := host.RemoveVLAN(*vlan)
		if err != nil {
			host.LogError(err, *vlan)
			return err
		}
	}
	for _, acl := range stateDiff.Removed.ACLs {
		err := host.RemoveACL(*acl)
		if err != nil {
			host.LogError(err, *acl)
			return err
		}
	}
	for _, snat := range stateDiff.Removed.SNATs {
		err := host.RemoveSNAT(*snat)
		if err != nil {
			host.LogError(err, *snat)
			return err
		}
	}
	for _, dnat := range stateDiff.Removed.DNATs {
		err := host.RemoveDNAT(*dnat)
		if err != nil {
			host.LogError(err, *dnat)
			return err
		}
	}
	for _, route := range stateDiff.Removed.Routes {
		err := host.RemoveRoute(*route)
		if err != nil {
			host.LogError(err, *route)
			return err
		}
	}

	if len(stateDiff.Added.BridgedVLANs) > 0 || len(stateDiff.Updated.BridgedVLANs) > 0 || len(stateDiff.Removed.BridgedVLANs) > 0 {
		err := host.runScript("post-change-vlan")
		if err != nil {
			return err
		}
	}

	return nil
}

func (host *linuxHost) runScript(scriptName string) (err error) {
	scriptPath := SCRIPTS_PATH+"/"+scriptName

	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return nil
	}

	err = host.exec(scriptPath)
	if err != nil {
		return err
	}

	return nil
}

func (host *linuxHost) InquireDHCP() (dhcp networkControl.DHCP) {
	// Scanning on the local machine only, so "accessDetails" is not supported, yet
	if host.accessDetails != nil {
		panic(errNotImplemented)
	}

	err := host.dhcpd.ReloadConfig()
	if err != nil && strings.Index(err.Error(), "no such file or directory") == -1 {
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
	vlans := host.inquireBridgedVLANs(netTree.GetTree().ToSlice(), vlanId)

	for _, vlan := range vlans {
		if vlan.VlanId != vlanId {
			continue
		}

		if vlan.Name == "" {
			host.Warningf("vlan %v has empty name. vlan == %v", vlan.VlanId, vlan)
			return nil
		}

		return vlan
	}

	return nil
}
func (host *linuxHost) inquireBridgedVLANs(ifaces netTree.Nodes, filterVlanIds ...int) networkControl.VLANs { // TODO: consider possibility of .1q in .1q
	host.Infof("host.inquireBridgedVLANs()")
	vlans := networkControl.VLANs{}

	filterVlanIdMap := map[int]bool{}
	if len(filterVlanIds) > 0 {
		for _, vlanId := range filterVlanIds {
			filterVlanIdMap[vlanId] = true
		}
	}

	for _, iface := range ifaces {
		link, ok := iface.Link.(*netlink.Vlan)
		if !ok {
			continue
		}

		if len(iface.Children) != 1 {
			// TODO: consider this case (not-bridged vlan iface)
			host.Warningf("len(iface.Children) != 1: %v", link)
			continue
		}
		child := iface.Children[0]
		childLink, ok := child.Link.(*netlink.Bridge)
		if !ok {
			// TODO: consider this case (not-bridged vlan iface)
			host.Warningf("!ok: %v", link)
			continue
		}

		if len(filterVlanIds) > 0 {
			if !filterVlanIdMap[link.VlanId] {
				continue
			}
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

		ifName := host.LinuxIfNameToIfName(childLink.Name)

		// Security-level
		securityLevel := host.GetFirewall().InquireSecurityLevel(ifName)

		vlans[link.VlanId] = &networkControl.VLAN{
			Interface: net.Interface{
				Name:         ifName,
				MTU:          childLink.MTU,
				HardwareAddr: childLink.HardwareAddr,
			},
			VlanId:        link.VlanId,
			IPs:           ips,
			SecurityLevel: securityLevel,
		}
	}

	host.Infof("len(vlans) == %v, len(ifaces.ToSlice()) == %v", len(vlans), len(ifaces.ToSlice()))

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
	ip = net.ParseIP(words[0])
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
				route.IfName = host.HostIfNameToIfName(words[1])
				words = words[2:]
			case "proto", "kernel", "scope", "link", "linkdown", "":
				words = words[1:]
			case "src":
				words = words[2:]
			case "from":
				var source networkControl.IPNet
				source, words = parseIPNet(words[1:])
				route.Sources = append(route.Sources, source)
				words = words[2:]
			case "metric":
				route.Metric, err = strconv.Atoi(words[1])
				words = words[2:]
			default:
				panic("unknown word: \"" + words[0] + "\"")
			}
		}
		if len(route.Sources) == 0 {
			route.Sources = networkControl.IPNets{networkControl.IPNet{IP: net.ParseIP("0.0.0.0"), Mask: net.IPv4Mask(0, 0, 0, 0)}}
		}

		result = append(result, &route)
	}

	for _, route := range result {
		host.Infof("host.InquireRoutes() route: %v", *route)
	}

	return
}

func (host *linuxHost) RescanState() error {
	oldIgnoredState := networkControl.State{}
	oldIgnoredState.CopyIgnoredFrom(host.States.Cur)

	host.States.Cur.BridgedVLANs = host.InquireBridgedVLANs()
	host.States.Cur.DHCP = host.InquireDHCP()
	host.States.Cur.ACLs = host.InquireACLs()
	host.States.Cur.SNATs = host.InquireSNATs()
	host.States.Cur.DNATs = host.InquireDNATs()
	host.States.Cur.Routes = host.InquireRoutes()

	host.States.Cur.CopyIgnoredFrom(oldIgnoredState)
	return nil
}
func (host *linuxHost) SetDHCPState(state networkControl.DHCP) error {
	host.dhcpd.Config.Root = cfg.Root(state)
	return nil
}

type netConfigT struct {
	VLANs  networkControl.VLANs
}

func (host *linuxHost) SaveToDisk() (err error) { // ATM, works only with Debian with preinstalled packages: "iproute2", "iptables" and "ipset"!
	host.Infof("linuxHost.SaveToDisk()")

	// vlans

	{
		netConfig := netConfigT{}
		netConfig.VLANs = host.States.Cur.BridgedVLANs
		netConfigJson, _ := json.MarshalIndent(netConfig, "", " ")
		err = ioutil.WriteFile(NETCONTOL_CONFIG_PATH, netConfigJson, 0644)
		if err != nil {
			host.LogError(err)
			return err
		}
	}

	// routes

	_, err = exec.Command("sh", "-c", "ip rule save > /etc/iproute.rules").Output()
	if err != nil {
		host.LogWarning(err)
	}
	_, err = exec.Command("sh", "-c", "ip route save > /etc/iproute.routes").Output()
	if err != nil {
		host.LogWarning(err)
	}

	// dhcp

	host.Debugf("linuxHost.SaveToDisk(): DHCP == %v (new: %v; old: %v)", host.States.Cur.DHCP, host.States.New.DHCP, host.States.Old.DHCP)
	host.SetDHCPState(host.States.Cur.DHCP)
	err = host.dhcpd.SaveConfig()
	if err != nil {
		host.LogError(err)
		return err
	}

	// iptables

	_, err = exec.Command("sh", "-c", "iptables-save > /etc/iptables/fwsm.rules").Output()
	if err != nil {
		host.LogError(err)
		return err
	}

	// ipset

	_, err = exec.Command("ipset", "save", "-file", "/etc/ipset-fwsm.dump").Output()
	if err != nil {
		host.LogError(err)
		return err
	}

	// finish

	return nil
}
func (host *linuxHost) RestoreFromDisk() error { // ATM, works only with Debian with preinstalled packages: "iproute2", "iptables" and "ipset"!
	host.RescanState()

	// vlans

	if _, err := os.Stat(NETCONTOL_CONFIG_PATH); err == nil {
		plan, err := ioutil.ReadFile(NETCONTOL_CONFIG_PATH)
		if err != nil {
			host.LogError(err)
			return err
		}
		netConfig := netConfigT{}
		err = json.Unmarshal(plan, &netConfig)
		if err != nil {
			host.LogError(err)
			return err
		}
		host.States.New.BridgedVLANs = netConfig.VLANs
		err = host.Apply()
		if err != nil {
			host.LogError(err)
			return err
		}
	}

	// routes

	if _, err := os.Stat("/etc/iproute.rules"); err == nil {
		exec.Command("ip", "rule", "flush").Output()
		exec.Command("ip", "rule", "del", "0").Output()
		exec.Command("ip", "rule", "del", "0").Output()
		exec.Command("ip", "rule", "del", "32766").Output()
		exec.Command("ip", "rule", "del", "32766").Output()
		exec.Command("ip", "rule", "del", "32767").Output()
		exec.Command("ip", "rule", "del", "32767").Output()
		_, err := exec.Command("sh", "-c", "ip rule restore < /etc/iproute.rules").Output()
		if err != nil {
			host.LogWarning(err)
		}
		exec.Command("ip", "rule", "add", "from", "all", "lookup", "local", "priority", "0").Output()
		exec.Command("ip", "rule", "add", "from", "all", "lookup", "main", "priority", "32766").Output()
		exec.Command("ip", "rule", "add", "from", "all", "lookup", "default", "priority", "32767").Output()
	}
	if _, err := os.Stat("/etc/iproute.routes"); err == nil {
		_, err := exec.Command("sh", "-c", "ip route restore < /etc/iproute.routes").Output()
		if err != nil {
			host.LogWarning(err, "ip route restore < /etc/iproute.routes")
		}
	}

	// ipset

	if _, err := os.Stat("/etc/ipset-fwsm.dump"); err == nil {
		_, err := exec.Command("ipset", "restore", "-file", "/etc/ipset-fwsm.dump").Output()
		if err != nil {
			host.LogWarning(err, "ipset", "restore", "-file", "/etc/ipset-fwsm.dump")
		}
	}

	// dhcp

	err := host.dhcpd.ReloadConfig()
	if err != nil && strings.Index(err.Error(), "no such file or directory") == -1 {
		host.LogWarning(err)
	}
	host.SetDHCPState(host.States.Cur.DHCP)

	// iptables

	if _, err := os.Stat("/etc/iptables/fwsm.rules"); err == nil {
		_, err := exec.Command("iptables-restore", "/etc/iptables/fwsm.rules").Output()
		if err != nil {
			host.LogWarning(err, "iptables-restore", "/etc/iptables/fwsm.rules")
		}
	}

	// finish

	return host.RescanState()
}
