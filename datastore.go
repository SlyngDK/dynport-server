package main

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/timshannon/badgerhold"
	"go.uber.org/zap"
	"net"
	"time"
)

type DataStore struct {
	l     *zap.Logger
	store *badgerhold.Store
}
type badgerLog struct {
	zap.SugaredLogger
}

func (b *badgerLog) Warningf(format string, args ...interface{}) {
	b.Warnf(format, args...)
}
func NewDataStore(logger *zap.Logger, dataDir string) (*DataStore, error) {
	options := badgerhold.DefaultOptions
	options.Dir = dataDir
	options.ValueDir = dataDir
	options.Logger = &badgerLog{*logger.Sugar()}

	store, err := badgerhold.Open(options)
	if err != nil {
		return nil, fmt.Errorf("failed to open badgerhold: %v", err)
	}

	return &DataStore{l: logger, store: store}, nil
}

func (d *DataStore) Close() error {
	return d.store.Close()
}

func (d *DataStore) GetLeases() ([]*PortMappingLease, error) {
	leases := make([]*PortMappingLease, 0)
	err := d.store.Find(&leases, &badgerhold.Query{})
	if err != nil {
		return nil, err
	}
	return leases, nil
}

func (d *DataStore) GetActiveLeases() ([]*PortMappingLease, error) {
	after := time.Now().Add(-(5 * time.Minute))

	leases := make([]*PortMappingLease, 0)
	err := d.store.Find(&leases, badgerhold.Where("LastSeen").Ge(after))
	if err != nil {
		return nil, err
	}
	return leases, nil
}

func (d *DataStore) UpsertLease(lease *PortMappingLease) error {
	leases := make([]*PortMappingLease, 0)
	err := d.store.Find(&leases, badgerhold.Where("Id").Eq(lease.Id))
	if err != nil {
		return err
	}
	if len(leases) == 0 {
		return d.store.Insert(lease.Id, lease)
	}
	leases[0].LastSeen = lease.LastSeen
	return d.store.Update(lease.Id, leases[0])
}

func (d *DataStore) GetLeaseById(id uuid.UUID) (*PortMappingLease, error) {
	l := &PortMappingLease{}
	err := d.store.Get(id, l)
	return nil, err
}

func (d *DataStore) GetLeaseByIpAndPort(ip net.IP, port uint16, protocol PROTOCOL) (*PortMappingLease, error) {
	leases := make([]*PortMappingLease, 0)

	err := d.store.Find(&leases, badgerhold.
		Where("ClientIP").Eq(ip).
		And("ClientPort").Eq(port).
		And("Protocol").Eq(protocol))
	if err != nil {
		return nil, err
	}

	if len(leases) == 1 {
		return leases[0], nil
	} else if len(leases) == 0 {
		return nil, nil
	}

	return nil, fmt.Errorf("multiple lease matching found")
}

func (d *DataStore) IsExternalPortInUse(port uint16) bool {
	leases := make([]*PortMappingLease, 0)
	err := d.store.Find(&leases, badgerhold.Where("ExternalPort").Eq(port))
	if err != nil {
		return true
	}
	return len(leases) > 0
}
