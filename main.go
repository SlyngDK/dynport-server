package main

import (
	"fmt"
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
	Id           string `badgerhold:"unique"`
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
	var err error
	logger := getLogger()
	defer logger.Sync() // flushes buffer, if any

	if config.ReplicationListenAddr != "" && config.ReplicationSecret == "" {
		logger.Fatal("you have enabled replication, but not specified a replication secret")
	}

	var externalIP net.IP
	if config.ExternalIP != "" {
		externalIP = net.ParseIP(config.ExternalIP)
	} else {
		externalIP, err = GetOutboundIP()
		if err != nil {
			logger.With(zap.Error(err)).Fatal("failed to guess external ip")
		}
	}

	ipt, err := NewIPTablesManager(logger, externalIP)
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

	replication := NewReplication(logger, store, config.ReplicationListenAddr, config.ReplicationSecret, config.ReplicationPeers)
	replication.RegisterUpdateListener(ipt.Reconcile)
	replication.Start()

	go func() {
		replication.RunFullSync()

		t := time.NewTimer(5 * time.Minute)
		for {
			select {
			case <-t.C:
				replication.RunFullSync()
			}
		}
	}()

	pcp, err := NewPCPServer(logger, ipt, store, config.ListenAddr, externalIP, config.ACL, config.ACLAllowDefault)
	if err != nil {
		logger.With(zap.Error(err)).Fatal("failed to create new pcp server")
	}
	pcp.RegisterListener(replication.PortMappingLeaseListener)
	err = pcp.Start()
	if err != nil {
		logger.With(zap.Error(err)).Error("failed to start pcp server")
	}
}

func GetOutboundIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP, nil
}
