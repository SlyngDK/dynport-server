package main

import (
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"github.com/google/go-cmp/cmp"
	"github.com/google/shlex"
	"go.uber.org/zap"
	"math/rand"
	"net"
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
	externalIP       net.IP
}

func NewIPTablesManager(l *zap.Logger, externalIP net.IP) (*IPTablesManager, error) {
	ipt, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv4))
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
		externalIP:       externalIP,
	}, nil
}

func (i *IPTablesManager) CheckPrerequisite(createChains, skipJumpCheck bool) error {
	if err := i.checkChain(table_filter, chain_port_mapping, createChains); err != nil {
		return err
	}
	if err := i.checkChain(table_nat, chain_port_mapping_prerouting, createChains); err != nil {
		return err
	}
	if err := i.checkChain(table_nat, chain_port_mapping_postrouting, createChains); err != nil {
		return err
	}

	if !skipJumpCheck {
		if ok, _ := i.jumpExist(table_filter, chain_forward, chain_port_mapping); !ok {
			return fmt.Errorf("table %s chain %s is missing jump to %s", table_filter, chain_forward, chain_port_mapping)
		}
		if ok, _ := i.jumpExist(table_nat, chain_prerouting, chain_port_mapping_prerouting); !ok {
			return fmt.Errorf("table %s chain %s is missing jump to %s", table_nat, chain_prerouting, chain_port_mapping_prerouting)
		}
		if ok, _ := i.jumpExist(table_nat, chain_postrouting, chain_port_mapping_postrouting); !ok {
			return fmt.Errorf("table %s chain %s is missing jump to %s", table_nat, chain_postrouting, chain_port_mapping_postrouting)
		}
	}

	return nil
}

func (i *IPTablesManager) checkChain(table, chain string, createTables bool) error {
	if ok, _ := i.ipt.ChainExists(table, chain); !ok {
		if createTables {
			err := i.ipt.NewChain(table, chain)
			if err != nil {
				return fmt.Errorf("failed to create chain %s %s %w", table, chain, err)
			}
		} else {
			return fmt.Errorf("%s table is missing %s chain", table, chain)
		}
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
	i.ensureIn(table_nat, chain_port_mapping_postrouting, postFix, leases, i.postroutingRule)

}

func forwardRule(lease *PortMappingLease) []string {
	return []string{
		"-d", fmt.Sprintf("%s/32", lease.ClientIP.String()),
		"-p", lease.Protocol.String(),
		"-m", lease.Protocol.String(), "--dport", strconv.Itoa(int(lease.ClientPort)),
		"-m", "comment", "--comment", lease.Id,
		"-j", "ACCEPT",
	}
}

func preroutingRule(lease *PortMappingLease) []string {
	return []string{
		"-p", lease.Protocol.String(),
		"-m", lease.Protocol.String(), "--dport", strconv.Itoa(int(lease.ExternalPort)),
		"-m", "comment", "--comment", lease.Id,
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", lease.ClientIP, lease.ClientPort),
	}
}

func (i *IPTablesManager) postroutingRule(lease *PortMappingLease) []string {
	return []string{
		"-s", fmt.Sprintf("%s/32", lease.ClientIP.String()),
		"-p", lease.Protocol.String(),
		"-m", lease.Protocol.String(), "--sport", strconv.Itoa(int(lease.ClientPort)),
		"-m", "comment", "--comment", lease.Id,
		"-j", "SNAT", "--to-source", fmt.Sprintf("%s:%d", i.externalIP.To4().String(), lease.ExternalPort),
	}
}

func (i *IPTablesManager) ensureIn(table, chainBase, postFix string, leases []*PortMappingLease, fn func(*PortMappingLease) []string) error {
	chain := chainBase + "-" + postFix

	// Generate rules
	newRules := make([][]string, 0)
	for _, lease := range leases {
		newRules = append(newRules, fn(lease))
	}
	currentRules := i.listCurrentChain(table, chainBase)

	if cmp.Diff(newRules, currentRules) == "" {
		i.l.Debugf("no new changes to chain %s %s", table, chain)
		return nil
	}

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
	for _, rule := range newRules {
		if err := i.ipt.AppendUnique(table, chain, rule...); err != nil {
			i.l.With(zap.Error(err)).Errorf("failed to ensure rule %s", rule)
			continue
		}
	}

	i.setActiveChain(table, chainBase, postFix)

	return nil
}

func (i *IPTablesManager) listCurrentChain(table, chain string) [][]string {
	list, err := i.ipt.List(table, chain)
	if err != nil {
		i.l.With(zap.Error(err)).Error("failed to list chain")
		return nil
	}
	rules2 := rulesToArgs(list)
	if len(rules2) != 1 {
		return nil
	}
	currentChain := ""
	for j, r := range rules2[0] {
		if r == "-j" {
			currentChain = rules2[0][j+1]
			break
		}
	}
	if currentChain == "" {
		return nil
	}

	list, err = i.ipt.List(table, currentChain)
	if err != nil {
		i.l.With(zap.Error(err)).Error("failed to list chain")
		return nil
	}

	return rulesToArgs(list)
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
