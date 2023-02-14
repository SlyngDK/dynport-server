package main

import (
	"fmt"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"net"
	"os"
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

var config Configuration

func main() {
	if err := NewRootCommand().Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func start() {
	logger := getLogger()
	defer logger.Sync() // flushes buffer, if any

	ipt, err := NewIPTablesManager(logger)
	if err != nil {
		logger.With(zap.Error(err)).Fatal("failed to create IPTablesManager")
	}
	defer ipt.Close()

	if err = ipt.CheckPrerequisite(config.CreateChains, config.SkipJumpCheck); err != nil {
		logger.With(zap.Error(err)).Fatal("prerequisite check failed")
	}

	store, err := NewDataStore(logger, config.DataDir)
	if err != nil {
		logger.With(zap.Error(err)).Fatal("failed to start datastore")
	}
	defer store.Close()

	go ipt.StartReconcile(store.GetActiveLeases)

	ipt.Reconcile()

	var externalIP net.IP
	if config.ExternalIP != "" {
		externalIP = net.ParseIP(config.ExternalIP)
	}

	pcp, err := NewPCPServer(logger, ipt, store, config.ListenAddr, externalIP)
	if err != nil {
		logger.With(zap.Error(err)).Fatal("failed to create new pcp server")
	}
	err = pcp.Start()
	if err != nil {
		logger.With(zap.Error(err)).Error("failed to start pcp server")
	}

	//defer pcp.Stop()
}
