package networkControl

import (
	"net"
	"strconv"
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
func (vlans *VLANs) SetSliceI(sliceI interface{}) {
	vlans.SetSlice(sliceI.([]*VLAN))
}
func (vlans *VLANs) SetSlice(slice []*VLAN) {
	newVLANs := VLANs{}
	for _, vlan := range slice {
		newVLANs[vlan.VlanId] = vlan
	}
	*vlans = newVLANs
}
func (vlan VLAN) KeyStringValue() string {
	return strconv.Itoa(vlan.VlanId)
}
