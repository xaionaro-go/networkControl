package fwsmHost

import (
	"github.com/xaionaro-go/networkControl"
	"github.com/xaionaro-go/networkControl/firewalls/fwsm"
)

const (
	errNotImplemented = error("not implemented, yet")
)

type AccessDetails struct {
	Host          string
	Slot          int
	Processor     int
	EntryPassword string
	FWSMPassword  string
}

type fwsmHost struct {
	networkControl.HostBase
	accessDetails *AccessDetails
}

func NewHost(accessDetails *AccessDetails) networkControl.HostI {
	host := fwsmHost{}
	host.HostBase.parent = &host
	if accessDetails != nil {
		accessDetailsCopy := *accessDetails
		host.accessDetails = &accessDetailsCopy
	} else {
		panic(errNotImplemented)
	}
	host.HostBase.SetFirewall(fwsm.NewFirewall())
	return &host
}

func (fwsmHost *fwsmHost) SetFirewall() error {
	panic(errNotImplemented)
	return errNotImplemented
}
