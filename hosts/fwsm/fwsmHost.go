package fwsmHost

import (
	"github.com/xaionaro-go/networkControl"
	"github.com/xaionaro-go/networkControl/firewalls/fwsm"
)

const (
	errNotImplemented = error("not implemented, yet")
)

type AccessDetails struct {
	Host string
	Slot int
	Processor int
	EntryPassword string
	FWSMPassword string
}

type fwsmHost struct {
	base networkControl.HostBase
	accessDetails *AccessDetails
}

func NewHost(accessDetails *AccessDetails) networkControl.HostI {
	host := fwsmHost{}
	if accessDetails != nil {
		accessDetailsCopy := *accessDetails
		host.accessDetails = &accessDetailsCopy
	} else {
		panic(errNotImplemented)
	}
	host.base.SetFirewall(fwsm.NewFirewall())
	return &host
}

func (fwsmHost *fwsmHost) SetFirewall() error {
	return errNotImplemented
}

func (fwsmHost *fwsmHost) AddBridgedVLAN(iface net.Interface) error {
	return errNotImplemented
}

