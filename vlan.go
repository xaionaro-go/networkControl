package networkControl

import (
	"fmt"
	"github.com/xaionaro-go/handySlices"
	"net"
	"strconv"
)

type VLAN struct {
	net.Interface
	VlanId        int
	IPs           IPNets
	SecurityLevel int
	IsIgnored     bool
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
func (vlan VLAN) IsEqualToI(compareToI handySlices.IsEqualToIer) bool {
	compareTo, ok := compareToI.(VLAN)
	if !ok {
		compareToPtr := compareToI.(*VLAN)
		compareTo = *compareToPtr
	}
	if vlan.VlanId != compareTo.VlanId {
		fmt.Println("vlan.VlanId != compareTo.VlanId", vlan.VlanId, compareTo.VlanId)
		return false
	}
	if vlan.SecurityLevel != compareTo.SecurityLevel {
		//fmt.Println("vlan.SecurityLevel != compareTo.SecurityLevel", vlan.SecurityLevel, compareTo.SecurityLevel)
		return false
	}
	if !vlan.IPs.IsEqualTo(compareTo.IPs) {
		//fmt.Println("!vlan.IPs.IsEqualTo(compareTo.IPs)")
		return false
	}
	if vlan.Name != compareTo.Name {
		//fmt.Println("vlan.Name != compareTo.Name", vlan.Name, compareTo.Name)
		return false
	}
	if vlan.MTU != compareTo.MTU {
		//fmt.Println("vlan.MTU != compareTo.MTU", vlan.MTU, compareTo.MTU)
		return false
	}

	return true
}
