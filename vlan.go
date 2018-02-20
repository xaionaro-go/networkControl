package networkControl

import (
	"net"
)

type VLAN struct {
	net.Interface
	VlanId        int
	IPs           IPNets
	SecurityLevel int
}

func NewVLAN(iface net.Interface) *VLAN {
	return &VLAN{Interface: iface}
}

type VLANs map[int]*VLAN

func (vlans VLANs) Get(vlanId int) VLAN {
	return *vlans[vlanId]
}
