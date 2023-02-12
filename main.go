package main

import (
	"github.com/google/uuid"
	"go.uber.org/zap"
	"net"
	"time"
)

type PROTOCOL uint8

const (
	TCP PROTOCOL = 0
	UDP          = 1
)

func (p PROTOCOL) String() string {
	switch p {
	case 0:
		return "tcp"
	case 1:
		return "udp"
	}
	return ""
}

type PortMappingLease struct {
	Id           uuid.UUID `badgerhold:"unique"`
	Created      time.Time
	LastSeen     time.Time
	ClientIP     net.IP
	ClientPort   uint16
	Protocol     PROTOCOL
	ExternalPort uint16 `badgerhold:"unique"`
}

func main() {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync() // flushes buffer, if any

	ipt, err := NewIPTablesManager(logger)
	if err != nil {
		logger.With(zap.Error(err)).Fatal("failed to create IPTablesManager")
	}
	defer ipt.Close()

	if err = ipt.CheckPrerequisite(); err != nil {
		logger.With(zap.Error(err)).Fatal("prerequisite check failed")
	}

	dataDir := "/tmp/pcp" // TODO
	store, err := NewDataStore(logger, dataDir)
	if err != nil {
		logger.With(zap.Error(err)).Fatal("failed to start datastore")
	}
	defer store.Close()

	go ipt.StartReconcile(store.GetActiveLeases)

	ipt.Reconcile()

	pcp := NewPCPServer(logger, ipt, store)
	err = pcp.Start()
	if err != nil {
		logger.With(zap.Error(err)).Error("failed to start pcp server")
	}

	//defer pcp.Stop()
}
