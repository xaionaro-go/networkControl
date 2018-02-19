package networkControl

import (
	"net"
)

type HostBase struct {
	firewall FirewallI
}

func (host HostBase) SetFirewall(newFirewall FirewallI) error {
	host.firewall = newFirewall
	return nil
}
func (host HostBase) GetFirewall() FirewallI {
	return host.firewall
}

type HostI interface {
	AddBridgedVLAN(net.Interface) error
	RemoveBridgedVLAN(int) error
	SetFirewall(FirewallI) error

	GetFirewall() FirewallI
}

type FirewallI interface {
}

type Hosts []HostI

func (hosts Hosts) SetFirewall(newFirewall FirewallI) error {
	for _, host := range hosts {
		err := host.SetFirewall(newFirewall)
		if err != nil {
			return err
		}
	}

	return nil
}

func (hosts Hosts) AddBridgedVLAN(iface net.Interface) error {
	for _, host := range hosts {
		err := host.AddBridgedVLAN(iface)
		if err != nil {
			return err
		}
	}

	return nil
}

func (hosts Hosts) RemoveBridgedVLAN(vlanId int) error {
	for _, host := range hosts {
		err := host.RemoveBridgedVLAN(vlanId)
		if err != nil {
			return err
		}
	}

	return nil
}

type Firewalls []FirewallI

func (hosts Hosts) GetFirewall() FirewallI {
	firewalls := Firewalls{}
	for _, host := range hosts {
		firewalls = append(firewalls, host.GetFirewall())
	}

	return firewalls
}


