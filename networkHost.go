package networkControl

import (
	"github.com/xaionaro-go/handySlices"
	"log"
)

type States struct {
	Old State
	New State
	Cur State
}

type FirewallBase struct {
	host HostI
}

func (fw FirewallBase) Debugf(fmt string, args ...interface{}) {
	fw.GetHost().Debugf(fmt, args...)
}
func (fw FirewallBase) Infof(fmt string, args ...interface{}) {
	fw.GetHost().Infof(fmt, args...)
}
func (fw FirewallBase) Warningf(fmt string, args ...interface{}) {
	fw.GetHost().Warningf(fmt, args...)
}
func (fw FirewallBase) Errorf(fmt string, args ...interface{}) {
	fw.GetHost().Errorf(fmt, args...)
}
func (fw FirewallBase) Panicf(fmt string, args ...interface{}) {
	fw.GetHost().Panicf(fmt, args...)
}
func (fw FirewallBase) LogWarning(err error, ctx ...interface{}) {
	fw.GetHost().LogWarning(err, ctx...)
}
func (fw FirewallBase) LogError(err error, ctx ...interface{}) {
	fw.GetHost().LogError(err, ctx...)
}
func (fw FirewallBase) LogPanic(err error, ctx ...interface{}) {
	fw.GetHost().LogPanic(err, ctx...)
}
func (fw FirewallBase) GetHost() HostI {
	return fw.host
}

func (fw *FirewallBase) SetHost(host HostI) error {
	if fw.host != nil {
		panic(errNotImplemented)
		return errNotImplemented
	}

	fw.host = host
	return nil
}

type HostBase struct {
	parent   HostI
	firewall FirewallI
	States   States

	loggerDebug   *log.Logger
	loggerInfo    *log.Logger
	loggerWarning *log.Logger
	loggerError   *log.Logger
	loggerPanic   *log.Logger
}

func (host *HostBase) SetParent(newParent HostI) error {
	if host.parent != nil {
		panic(errNotImplemented)
		return errNotImplemented
	}

	host.parent = newParent
	return nil
}
func (host *HostBase) SetLoggerDebug(newLogger *log.Logger) {
	host.loggerDebug = newLogger
}
func (host *HostBase) SetLoggerInfo(newLogger *log.Logger) {
	host.loggerInfo = newLogger
}
func (host *HostBase) SetLoggerWarning(newLogger *log.Logger) {
	host.loggerWarning = newLogger
}
func (host *HostBase) SetLoggerError(newLogger *log.Logger) {
	host.loggerError = newLogger
}
func (host *HostBase) SetLoggerPanic(newLogger *log.Logger) {
	host.loggerPanic = newLogger
}
func (host HostBase) Debugf(fmt string, args ...interface{}) {
	if host.loggerDebug == nil {
		return
	}
	host.loggerDebug.Printf("[D] "+fmt, args...)
}
func (host HostBase) Infof(fmt string, args ...interface{}) {
	if host.loggerInfo == nil {
		return
	}
	host.loggerInfo.Printf("[I] "+fmt, args...)
}
func (host HostBase) Warningf(fmt string, args ...interface{}) {
	if host.loggerWarning == nil {
		return
	}
	host.loggerWarning.Printf("[W] "+fmt, args...)
}
func (host HostBase) Errorf(fmt string, args ...interface{}) {
	if host.loggerError == nil {
		return
	}
	host.loggerError.Printf("[E] "+fmt, args...)
}
func (host HostBase) Panicf(fmt string, args ...interface{}) {
	if host.loggerPanic == nil {
		return
	}
	host.loggerPanic.Printf("[P] "+fmt, args...)
}
func (host HostBase) LogError(err error, ctx ...interface{}) {
	host.Errorf("Got an error: %v [%v]", err.Error(), ctx)
}
func (host HostBase) LogWarning(err error, ctx ...interface{}) {
	host.Warningf("Got an error: %v [%v]", err.Error(), ctx)
}
func (host HostBase) LogPanic(err error, ctx ...interface{}) {
	host.Panicf("panic: %v [%v]", err.Error(), ctx)
}

func (host *HostBase) SetFirewall(newFirewall FirewallI) error {
	host.firewall = newFirewall
	return nil
}
func (host HostBase) GetFirewall() FirewallI {
	return host.firewall
}
func (host *HostBase) AddBridgedVLAN(vlan VLAN) (err error) {
	return host.States.New.AddBridgedVLAN(vlan)
}
func (host *HostBase) RemoveBridgedVLAN(vlanId int) error {
	return host.States.New.RemoveBridgedVLAN(vlanId)
}
func (host *HostBase) SetNewState(newState State) error {
	host.States.New = newState
	return nil
}
func (host HostBase) GetVLAN(vlanId int) VLAN {
	return host.States.Cur.GetVLAN(vlanId)
}
func (host *HostBase) Apply() error {
	handySlices.Debugf = host.Debugf
	host.States.New.CopyIgnoredFrom(host.States.Cur)
	stateDiff := host.States.New.Diff(host.States.Cur)
	err1 := host.parent.ApplyDiff(stateDiff)
	host.States.Cur = host.States.New
	err2 := host.RescanState()
	if err1 != nil {
		return err1
	}
	return err2
}
func (host *HostBase) ApplySave() error {
	err := host.Apply()
	if err != nil {
		return err
	}
	return host.Save()
}
func (host *HostBase) Revert() error {
	host.States.New = host.States.Old
	return nil
}
func (host *HostBase) RevertApply() error {
	err := host.Revert()
	if err != nil {
		return err
	}
	return host.Apply()
}
func (host *HostBase) Save() error {
	host.States.Old = host.States.Cur
	return host.parent.SaveToDisk()
}
func (host *HostBase) RescanState() error {
	return host.parent.RescanState()
}
func (host HostBase) GetCurState() State {
	return host.States.Cur
}

type HostI interface {
	AddBridgedVLAN(VLAN) error
	RemoveBridgedVLAN(vlanId int) error
	SetFirewall(FirewallI) error

	GetFirewall() FirewallI

	GetVLAN(vlanId int) VLAN
	IfNameToHostIfName(string) string
	HostIfNameToIfName(string) string

	SetNewState(newState State) error

	Apply() error
	ApplySave() error
	Save() error
	SaveToDisk() error
	Revert() error
	RevertApply() error

	RestoreFromDisk() error

	ApplyDiff(StateDiff) error
	RescanState() error

	GetCurState() State

	SetLoggerDebug(*log.Logger)
	SetLoggerInfo(*log.Logger)
	SetLoggerWarning(*log.Logger)
	SetLoggerError(*log.Logger)
	SetLoggerPanic(*log.Logger)

	Debugf(fmt string, args ...interface{})
	Infof(fmt string, args ...interface{})
	Warningf(fmt string, args ...interface{})
	Errorf(fmt string, args ...interface{})
	Panicf(fmt string, args ...interface{})
	LogWarning(err error, ctx ...interface{})
	LogError(err error, ctx ...interface{})
	LogPanic(err error, ctx ...interface{})
}

type FirewallI interface {
	InquireSecurityLevel(ifName string) int
	InquireACLs() ACLs
	InquireSNATs() SNATs
	InquireDNATs() DNATs

	AddACL(ACL) error
	AddSNAT(SNAT) error
	AddDNAT(DNAT) error
	UpdateACL(ACL) error
	UpdateSNAT(SNAT) error
	UpdateDNAT(DNAT) error
	RemoveACL(ACL) error
	RemoveSNAT(SNAT) error
	RemoveDNAT(DNAT) error

	SetSecurityLevel(ifName string, securityLevel int) error

	SetEnablePermitInterInterface(bool) error
	SetEnablePermitIntraInterface(bool) error
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

func (hosts Hosts) Debugf(fmt string, args ...interface{}) {
	panic(errNotImplemented)
}
func (hosts Hosts) Infof(fmt string, args ...interface{}) {
	panic(errNotImplemented)
}
func (hosts Hosts) Warningf(fmt string, args ...interface{}) {
	panic(errNotImplemented)
}
func (hosts Hosts) Errorf(fmt string, args ...interface{}) {
	panic(errNotImplemented)
}
func (hosts Hosts) Panicf(fmt string, args ...interface{}) {
	panic(errNotImplemented)
}
func (hosts Hosts) LogWarning(err error, ctx ...interface{}) {
	panic(errNotImplemented)
}
func (hosts Hosts) LogError(err error, ctx ...interface{}) {
	panic(errNotImplemented)
}
func (hosts Hosts) LogPanic(err error, ctx ...interface{}) {
	panic(errNotImplemented)
}

func (hosts Hosts) GetFirewall() FirewallI {
	firewalls := Firewalls{}
	for _, host := range hosts {
		firewalls = append(firewalls, host.GetFirewall())
	}

	return firewalls
}

func (hosts Hosts) GetVLAN(vlanId int) VLAN {
	panic(errNotImplemented)
	return VLAN{}
}
func (hosts Hosts) SetLoggerDebug(newLogger *log.Logger) {
	for _, host := range hosts {
		host.SetLoggerDebug(newLogger)
	}
	return
}
func (hosts Hosts) SetLoggerInfo(newLogger *log.Logger) {
	for _, host := range hosts {
		host.SetLoggerInfo(newLogger)
	}
	return
}
func (hosts Hosts) SetLoggerWarning(newLogger *log.Logger) {
	for _, host := range hosts {
		host.SetLoggerWarning(newLogger)
	}
	return
}
func (hosts Hosts) SetLoggerError(newLogger *log.Logger) {
	for _, host := range hosts {
		host.SetLoggerError(newLogger)
	}
	return
}
func (hosts Hosts) SetLoggerPanic(newLogger *log.Logger) {
	for _, host := range hosts {
		host.SetLoggerPanic(newLogger)
	}
	return
}
func (hosts Hosts) SetNewState(newState State) error {
	for _, host := range hosts {
		err := host.SetNewState(newState)
		if err != nil {
			return err
		}
	}
	return nil
}
func (hosts Hosts) GetCurState() State {
	panic(errNotImplemented)
}
func (hosts Hosts) GetCurStates() (states []State) {
	for _, host := range hosts {
		states = append(states, host.GetCurState())
	}
	return
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
func (hosts Hosts) IfNameToHostIfName(string) string {
	panic(errNotImplemented)
}
func (hosts Hosts) HostIfNameToIfName(string) string {
	panic(errNotImplemented)
}
func (firewalls Firewalls) InquireSecurityLevel(string) int {
	panic(errNotImplemented)
	return -1
}
func (firewalls Firewalls) InquireACLs() ACLs {
	panic(errNotImplemented)
	return ACLs{}
}
func (firewalls Firewalls) InquireSNATs() SNATs {
	panic(errNotImplemented)
	return SNATs{}
}
func (firewalls Firewalls) InquireDNATs() DNATs {
	panic(errNotImplemented)
	return DNATs{}
}
func (firewalls Firewalls) AddACL(acl ACL) error {
	panic(errNotImplemented)
	return nil
}
func (firewalls Firewalls) AddSNAT(snat SNAT) error {
	panic(errNotImplemented)
	return nil
}
func (firewalls Firewalls) AddDNAT(dnat DNAT) error {
	panic(errNotImplemented)
	return nil
}
func (firewalls Firewalls) UpdateACL(acl ACL) error {
	panic(errNotImplemented)
	return nil
}
func (firewalls Firewalls) UpdateSNAT(snat SNAT) error {
	panic(errNotImplemented)
	return nil
}
func (firewalls Firewalls) UpdateDNAT(dnat DNAT) error {
	panic(errNotImplemented)
	return nil
}
func (firewalls Firewalls) RemoveACL(acl ACL) error {
	panic(errNotImplemented)
	return nil
}
func (firewalls Firewalls) RemoveSNAT(snat SNAT) error {
	panic(errNotImplemented)
	return nil
}
func (firewalls Firewalls) RemoveDNAT(dnat DNAT) error {
	panic(errNotImplemented)
	return nil
}
func (firewalls Firewalls) SetSecurityLevel(ifName string, securityLevel int) error {
	panic(errNotImplemented)
	return nil
}
func (firewalls Firewalls) SetEnablePermitInterInterface(enable bool) error {
	panic(errNotImplemented)
	return nil
}
func (firewalls Firewalls) SetEnablePermitIntraInterface(enable bool) error {
	panic(errNotImplemented)
	return nil
}
