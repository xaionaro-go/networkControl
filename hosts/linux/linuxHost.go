package linuxHost

import (
	"errors"
	"github.com/xaionaro-go/networkControl"
	"github.com/xaionaro-go/networkControl/firewalls/iptables"
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

func (linuxHost *linuxHost) SetFirewall(newFirewall networkControl.FirewallI) error {
	return errNotImplemented
}
func (linuxHost linuxHost) GetFirewall() networkControl.FirewallI {
	return linuxHost.HostBase.GetFirewall()
}

func (linuxHost *linuxHost) ApplyDiff(stateDiff networkControl.StateDiff) error {
	return errNotImplemented
}
func (linuxHost *linuxHost) RescanState() error {
	return errNotImplemented
}
func (linuxHost *linuxHost) SaveToDisk() error { // ATM, works only with Debian with preinstalled packages: "iptables" and "ipset"!
	return errNotImplemented
}
func (linuxHost *linuxHost) RestoreFromDisk() error { // ATM, works only with Debian with preinstalled packages: "iptables" and "ipset"!
	return errNotImplemented
}

