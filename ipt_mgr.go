package main

import (
	"fmt"
	"github.com/google/shlex"
	"github.com/slyngdk/go-iptables/iptables"
	"go.uber.org/zap"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

const (
	table_filter                   = "filter"
	table_nat                      = "nat"
	chain_forward                  = "FORWARD"
	chain_prerouting               = "PREROUTING"
	chain_postrouting              = "POSTROUTING"
	chain_port_mapping             = "port-mapping"
	chain_port_mapping_prerouting  = chain_port_mapping + "-pre"
	chain_port_mapping_postrouting = chain_port_mapping + "-post"
)

type IPTablesManager struct {
	l                *zap.SugaredLogger
	ipt              *iptables.IPTables
	reconcileCh      chan interface{}
	reconcileCloseCh chan interface{}
}

func NewIPTablesManager(l *zap.Logger) (*IPTablesManager, error) {
	ipt, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv4), iptables.Sudo())
	if err != nil {
		return nil, fmt.Errorf("failed to create iptables instance, %v", err)
	}
	reconcileCh := make(chan interface{})
	reconcileCloseCh := make(chan interface{})
	return &IPTablesManager{
		l:                l.Sugar(),
		ipt:              ipt,
		reconcileCh:      reconcileCh,
		reconcileCloseCh: reconcileCloseCh,
	}, nil
}

func (i *IPTablesManager) CheckPrerequisite() error {
	if ok, _ := i.ipt.ChainExists(table_filter, chain_port_mapping); !ok {
		return fmt.Errorf("%s table is missing %s chain", table_filter, chain_port_mapping)
	}
	if ok, _ := i.ipt.ChainExists(table_nat, chain_port_mapping_postrouting); !ok {
		return fmt.Errorf("%s table is missing %s chain", table_nat, chain_port_mapping_postrouting)
	}
	if ok, _ := i.ipt.ChainExists(table_nat, chain_port_mapping_prerouting); !ok {
		return fmt.Errorf("%s table is missing %s chain", table_nat, chain_port_mapping_prerouting)
	}

	if ok, _ := i.jumpExist(table_filter, chain_forward, chain_port_mapping); !ok {
		return fmt.Errorf("table %s chain %s is missing jump to %s", table_filter, chain_forward, chain_port_mapping)
	}
	if ok, _ := i.jumpExist(table_nat, chain_prerouting, chain_port_mapping_prerouting); !ok {
		return fmt.Errorf("table %s chain %s is missing jump to %s", table_nat, chain_prerouting, chain_port_mapping_prerouting)
	}
	if ok, _ := i.jumpExist(table_nat, chain_postrouting, chain_port_mapping_postrouting); !ok {
		return fmt.Errorf("table %s chain %s is missing jump to %s", table_nat, chain_postrouting, chain_port_mapping_postrouting)
	}

	return nil
}

func (i *IPTablesManager) StartReconcile(leasesFn func() ([]*PortMappingLease, error)) {
	timer := time.NewTicker(2 * time.Minute)
	reconcileFn := func() {
		i.l.Debug("reconcile iptables")
		leases, err := leasesFn()
		if err != nil {
			return
		}
		i.EnsureMappings(leases)
	}
	for {
		select {
		case <-timer.C:
			reconcileFn()
		case <-i.reconcileCh:
			reconcileFn()
		case <-i.reconcileCloseCh:

			return
		}
	}
}

func (i *IPTablesManager) Close() {
	i.reconcileCloseCh <- true
}

func (i *IPTablesManager) Reconcile() {
	i.reconcileCh <- true
}

func (i *IPTablesManager) jumpExist(table, chain, target string) (bool, error) {
	list, err := i.ipt.List(table, chain)
	if err != nil {
		return false, err
	}
	for _, rule := range list {
		args, err := shlex.Split(rule)
		if err != nil {
			i.l.With(zap.Error(err)).Warn("failed to parse rule")
			continue
		}
		if len(args) == 0 || args[0] == "-N" {
			continue
		}
		for j, s := range args {
			if s == "-j" && args[j+1] == target {
				return true, nil
			}
		}
	}
	return false, nil
}

func (i *IPTablesManager) EnsureMappings(leases []*PortMappingLease) {
	postFix := RandStringBytes(6)
	i.ensureIn(table_filter, chain_port_mapping, postFix, leases, forwardRule)
	i.ensureIn(table_nat, chain_port_mapping_prerouting, postFix, leases, preroutingRule)
	i.ensureIn(table_nat, chain_port_mapping_postrouting, postFix, leases, postroutingRule)

}

func forwardRule(lease *PortMappingLease) []string {
	return []string{
		"-d", lease.ClientIP.String(),
		"-p", lease.Protocol.String(),
		"-m", lease.Protocol.String(), "--dport", strconv.Itoa(int(lease.ClientPort)),
		"-m", "comment", "--comment", lease.Id.String(),
		"-j", "ACCEPT"}
}

func preroutingRule(lease *PortMappingLease) []string {
	return []string{
		"-p", lease.Protocol.String(),
		"-m", lease.Protocol.String(), "--dport", strconv.Itoa(int(lease.ExternalPort)),
		"-m", "comment", "--comment", lease.Id.String(),
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", lease.ClientIP, lease.ClientPort)}
}

func postroutingRule(lease *PortMappingLease) []string {
	return []string{
		"-s", lease.ClientIP.String(),
		"-p", lease.Protocol.String(),
		"-m", lease.Protocol.String(), "--sport", strconv.Itoa(int(lease.ClientPort)),
		"-m", "comment", "--comment", lease.Id.String(),
		"-j", "MASQUERADE", "--to-ports", strconv.Itoa(int(lease.ExternalPort))}
}

func (i *IPTablesManager) ensureIn(table, chainBase, postFix string, leases []*PortMappingLease, fn func(*PortMappingLease) []string) error {
	chain := chainBase + "-" + postFix
	if ok, _ := i.ipt.ChainExists(table, chain); ok {
		err := i.ipt.ClearChain(table, chain)
		if err != nil {
			return err
		}
	} else {
		err := i.ipt.NewChain(table, chain)
		if err != nil {
			return err
		}
	}
	for _, lease := range leases {
		args := fn(lease)

		if err := i.ipt.AppendUnique(table, chain, args...); err != nil {
			i.l.With(zap.Error(err)).Errorf("failed to ensure rule %s", args)
			continue
		}
	}

	i.setActiveChain(table, chainBase, postFix)

	return nil
}

func (i *IPTablesManager) setActiveChain(table, chainBase, postFix string) {
	err := i.ipt.Insert(table, chainBase, 1, []string{"-j", chainBase + "-" + postFix}...)
	if err != nil {
		i.l.With(zap.Error(err)).Errorf("failed to add jump to new chain")
		return
	}
	rules, err := i.ipt.List(table, chainBase)
	if err != nil {
		i.l.With(zap.Error(err)).Errorf("failed to list chain %s %s", table, chainBase)
		return
	}
	for j, args := range rulesToArgs(rules) {
		if j == 0 {
			continue
		}
		err := i.ipt.Delete(table, chainBase, args...)
		if err != nil {
			i.l.With(zap.Error(err)).Errorf("failed to delete rule from %s %s", table, chainBase)
			return
		}
	}
	i.removeUsedChains(table, chainBase, postFix)
}

func (i *IPTablesManager) removeUsedChains(table, chainBase, postFix string) {
	chains, err := i.ipt.ListChains(table)
	if err != nil {
		i.l.With(zap.Error(err)).Errorf("failed to list chains in %s", table)
		return
	}

	for _, chain := range chains {
		if strings.HasPrefix(chain, chainBase+"-") && chain != chainBase+"-"+postFix {
			i.l.Debugf("flushing and deleting chain %s %s", table, chain)
			err := i.ipt.ClearAndDeleteChain(table, chain)
			if err != nil {
				i.l.With(zap.Error(err)).Errorf("failed to failed to flush and delete chain %s %s", table, chain)
				continue
			}
		}
	}
}

func rulesToArgs(rules []string) [][]string {
	result := make([][]string, 0)
	for _, rule := range rules {
		args, err := shlex.Split(rule)
		if err != nil {
			continue
		}
		if len(args) == 0 || args[0] == "-N" {
			continue
		}

		if args[0] == "-A" {
			args = args[2:]
		}

		result = append(result, args)
	}
	return result
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}