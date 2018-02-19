package networkControl

import ()

type states struct {
	Old State
	New State
	Cur State
}

type HostBase struct {
	states   states
	parent   HostI
	firewall FirewallI
}

func (host HostBase) SetParent(newParent HostI) error {
	if host.parent != nil {
		return errNotImplemented
	}

	host.parent = newParent
	return nil
}
func (host HostBase) SetFirewall(newFirewall FirewallI) error {
	host.firewall = newFirewall
	return nil
}
func (host HostBase) GetFirewall() FirewallI {
	return host.firewall
}
func (host *HostBase) AddBridgedVLAN(vlan VLAN) (err error) {
	return host.states.New.AddBridgedVLAN(vlan)
}
func (host *HostBase) RemoveBridgedVLAN(vlanId int) error {
	return host.states.New.RemoveBridgedVLAN(vlanId)
}
func (host HostBase) GetVLAN(vlanId int) VLAN {
	return host.states.Cur.GetVLAN(vlanId)
}
func (host HostBase) Apply() error {
	stateDiff := host.states.New.Diff(host.states.Cur)
	err1 := host.parent.ApplyDiff(stateDiff)
	err2 := host.RescanState()
	if err1 != nil {
		return err1
	}
	return err2
}
func (host HostBase) ApplySave() error {
	err := host.Apply()
	if err != nil {
		return err
	}
	return host.Save()
}
func (host HostBase) Revert() error {
	host.states.New = host.states.Old
	return nil
}
func (host HostBase) RevertApply() error {
	err := host.Revert()
	if err != nil {
		return err
	}
	return host.Apply()
}
func (host HostBase) Save() error {
	host.states.Old = host.states.Cur
	return host.parent.SaveToDisk()
}
func (host HostBase) RescanState() error {
	return host.parent.RescanState()
}

type HostI interface {
	AddBridgedVLAN(VLAN) error
	RemoveBridgedVLAN(vlanId int) error
	SetFirewall(FirewallI) error

	GetFirewall() FirewallI

	GetVLAN(vlanId int) VLAN

	Apply() error
	ApplySave() error
	Save() error
	SaveToDisk() error
	Revert() error
	RevertApply() error

	RestoreFromDisk() error

	ApplyDiff(StateDiff) error
	RescanState() error
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

func (hosts Hosts) AddBridgedVLAN(vlan VLAN) error {
	for _, host := range hosts {
		err := host.AddBridgedVLAN(vlan)
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

func (hosts Hosts) GetVLAN(vlanId int) VLAN {
	panic("Not implemented, yet")
	return VLAN{}
}
func (hosts Hosts) Apply() error {
	for _, host := range hosts {
		err := host.Apply()
		if err != nil {
			return err
		}
	}
	return nil
}
func (hosts Hosts) ApplySave() error {
	for _, host := range hosts {
		err := host.ApplySave()
		if err != nil {
			return err
		}
	}
	return nil
}
func (hosts Hosts) Save() error {
	for _, host := range hosts {
		err := host.Save()
		if err != nil {
			return err
		}
	}
	return nil
}
func (hosts Hosts) SaveToDisk() error {
	for _, host := range hosts {
		err := host.SaveToDisk()
		if err != nil {
			return err
		}
	}
	return nil
}
func (hosts Hosts) Revert() error {
	for _, host := range hosts {
		err := host.Revert()
		if err != nil {
			return err
		}
	}
	return nil
}
func (hosts Hosts) RevertApply() error {
	for _, host := range hosts {
		err := host.RevertApply()
		if err != nil {
			return err
		}
	}
	return nil
}
func (hosts Hosts) RestoreFromDisk() error {
	for _, host := range hosts {
		err := host.RestoreFromDisk()
		if err != nil {
			return err
		}
	}
	return nil
}
func (hosts Hosts) ApplyDiff(stateDiff StateDiff) error {
	for _, host := range hosts {
		err := host.ApplyDiff(stateDiff)
		if err != nil {
			return err
		}
	}
	return nil
}
func (hosts Hosts) RescanState() error {
	for _, host := range hosts {
		err := host.RescanState()
		if err != nil {
			return err
		}
	}
	return nil
}
