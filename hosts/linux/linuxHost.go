package linuxHost

import (
	"errors"
	"github.com/xaionaro-go/networkControl"
	"github.com/xaionaro-go/networkControl/firewalls/iptables"
	"net"
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
	base networkControl.HostBase
	accessDetails *AccessDetails
}

func NewHost(accessDetails *AccessDetails) networkControl.HostI {
	host := linuxHost{}
	if accessDetails != nil {
		panic(errNotImplemented)
		accessDetailsCopy := *accessDetails
		host.accessDetails = &accessDetailsCopy
	}
	host.base.SetFirewall(iptables.NewFirewall())
	return &host
}

func (linuxHost *linuxHost) SetFirewall(newFirewall networkControl.FirewallI) error {
	return errNotImplemented
}
func (linuxHost linuxHost) GetFirewall() networkControl.FirewallI {
	return linuxHost.base.GetFirewall()
}

func (linuxHost *linuxHost) AddBridgedVLAN(iface net.Interface) error {
	return errNotImplemented
}
func (linuxHost *linuxHost) RemoveBridgedVLAN(vlanId int) error {
	return errNotImplemented
}

