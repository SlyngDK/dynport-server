package main

import (
	"dynport-server/xdpnatforward"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket/routing"
	"go.uber.org/zap"
	"net"
	"net/netip"
	"time"
)

type EBPFManager struct {
	l                *zap.SugaredLogger
	reconcileCh      chan interface{}
	reconcileCloseCh chan interface{}
	externalIP       net.IP
	enabled          bool
	interfaceIndices []int
	xdp              *xdpnatforward.XDPProgram
}

func NewEBPFManager(l *zap.Logger, externalIP net.IP, enabled bool, listenAddrs []string) (*EBPFManager, error) {
	l = l.Named("ebpf")

	var interfaceIndices []int

	if enabled {
		interfaceIndicesSet := make(map[int]interface{})

		router, err := routing.New()
		if err != nil {
			return nil, err
		}
		iface, _, _, err := router.Route(externalIP)
		if err != nil {
			return nil, err
		}
		interfaceIndicesSet[iface.Index] = true

		for _, a := range listenAddrs {
			addrPort, err := netip.ParseAddrPort(a)
			if err != nil {
				return nil, err
			}

			iface, _, _, err := router.Route(net.ParseIP(addrPort.Addr().String()))
			if err != nil {
				return nil, err
			}
			interfaceIndicesSet[iface.Index] = true
		}
		for i := range interfaceIndicesSet {
			interfaceIndices = append(interfaceIndices, i)
		}
	}
	reconcileCh := make(chan interface{}, 2)
	reconcileCloseCh := make(chan interface{}, 2)
	return &EBPFManager{
		l:                l.Sugar(),
		reconcileCh:      reconcileCh,
		reconcileCloseCh: reconcileCloseCh,
		externalIP:       externalIP,
		enabled:          enabled,
		interfaceIndices: interfaceIndices,
	}, nil
}

func (e *EBPFManager) Load() error {
	if e.enabled {
		xdp, err := xdpnatforward.LoadNatForward(nil)
		if err != nil {
			return fmt.Errorf("error: failed to load xdp program: %w\n", err)
		}
		e.xdp = xdp

		for _, Ifindex := range e.interfaceIndices {
			if err := e.xdp.Program.Attach(Ifindex); err != nil {
				// Detach from all interface, if attach failed
				for _, IfindexClose := range e.interfaceIndices {
					err := e.xdp.Program.Detach(IfindexClose)
					if err != nil {
						e.l.Error(err)
					}
				}
				return fmt.Errorf("error: failed to attach xdp program to interface: %w\n", err)
			}
		}
	}
	return nil
}

func (e *EBPFManager) StartReconcile(leasesFn func() ([]*PortMappingLease, error)) {
	timer := time.NewTicker(2 * time.Minute)

	reconcileFn := func() {
		if !e.enabled {
			return
		}
		e.l.Debug("reconcile")
		leases, err := leasesFn()
		if err != nil {
			return
		}
		e.EnsureMappings(leases)
	}
	for {
		select {
		case <-timer.C:
			reconcileFn()
		case <-e.reconcileCh:
			reconcileFn()
		case <-e.reconcileCloseCh:

			return
		}
	}
}

func (e *EBPFManager) Close() {
	e.reconcileCloseCh <- true
	if e.xdp != nil {

		for _, IfindexClose := range e.interfaceIndices {
			err := e.xdp.Program.Detach(IfindexClose)
			if err != nil {
				e.l.Error(err)
			}
		}

		e.xdp.Close()
	}

}

func (e *EBPFManager) Reconcile() {
	e.reconcileCh <- true
}

func (e *EBPFManager) EnsureMappings(leases []*PortMappingLease) {
	sourceKeys := make(map[[6]byte]interface{})
	destinationKeys := make(map[[6]byte]interface{})

	for _, lease := range leases {
		if lease.Protocol != UDP {
			continue
		}
		m := xdpnatforward.Mapping{
			PublicIP:    e.externalIP,
			PublicPort:  lease.ExternalPort,
			PrivateIP:   lease.ClientIP,
			PrivatePort: lease.ClientPort,
		}
		sourceKey, sourceMap, err := xdpnatforward.GetSource(m)
		if err != nil {
			e.l.With(zap.Error(err)).Error("failed to get source")
			continue
		}
		sourceKeys[[6]byte(sourceKey)] = true

		e.l.Debugf("updating source %s:%d", m.PrivateIP, m.PrivatePort)
		err = e.xdp.Objs.Sources.Put(sourceKey, sourceMap)
		if err != nil {
			e.l.With(zap.Error(err)).Error("failed to put source")
			continue
		}
		destinationKey, destinationMap, err := xdpnatforward.GetDestination(m)
		if err != nil {
			e.l.With(zap.Error(err)).Error("failed to get source")
			continue
		}
		destinationKeys[[6]byte(destinationKey)] = true

		e.l.Debugf("updating destination %s:%d", m.PublicIP, m.PublicPort)
		err = e.xdp.Objs.Destinations.Put(destinationKey, destinationMap)
		if err != nil {
			e.l.With(zap.Error(err)).Error("failed to put destination")
			continue
		}
	}

	var (
		key [6]byte
		val []byte
	)
	e.l.Debug("cleanup old sources")
	iter := e.xdp.Objs.Sources.Iterate()
	for iter.Next(&key, &val) {
		if _, ok := sourceKeys[key]; !ok {
			ip := net.IP(key[0:4])
			port := binary.BigEndian.Uint16(key[4:6])
			e.l.Debugf("remove old source: %s:%d", ip, port)
			err := e.xdp.Objs.Sources.Delete(key)
			if err != nil {
				e.l.With(zap.Error(err)).Error("failed to delete source")
			}
		}
	}
	if iter.Err() != nil {
		e.l.With(zap.Error(iter.Err())).Error("failed to cleanup sources")
	}
	e.l.Debug("cleanup old destinations")
	iter = e.xdp.Objs.Destinations.Iterate()
	for iter.Next(&key, &val) {
		if _, ok := destinationKeys[key]; !ok {
			ip := net.IP(key[0:4])
			port := binary.BigEndian.Uint16(key[4:6])
			e.l.Debugf("remove old destination: %s:%d", ip, port)
			err := e.xdp.Objs.Destinations.Delete(key)
			if err != nil {
				e.l.With(zap.Error(err)).Error("failed to delete destination")
			}
		}
	}
	if iter.Err() != nil {
		e.l.With(zap.Error(iter.Err())).Error("failed to cleanup destinations")
	}

}
