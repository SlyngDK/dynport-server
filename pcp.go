package main

import (
	"fmt"
	"go.uber.org/zap"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

type PCPServer struct {
	conn         net.PacketConn
	externalIP   net.IP
	ipt          *IPTablesManager
	l            *zap.SugaredLogger
	listenAddr   string
	started      time.Time
	store        *DataStore
	acl          []ACLConfiguration
	allowDefault bool
	listeners    []func(lease PortMappingLease)
}

func NewPCPServer(
	l *zap.Logger,
	ipt *IPTablesManager,
	store *DataStore,
	listenAddr string,
	externalIP net.IP,
	acl []ACLConfiguration,
	allowDefault bool,
) (*PCPServer, error) {
	p := &PCPServer{
		l:            l.Sugar(),
		ipt:          ipt,
		store:        store,
		listenAddr:   listenAddr,
		externalIP:   externalIP,
		acl:          acl,
		allowDefault: allowDefault,
	}
	return p, nil
}

func (p *PCPServer) Start() error {
	p.started = time.Now()
	var err error
	p.conn, err = net.ListenPacket("udp4", p.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen for udp4 on `%s`: %v", p.listenAddr, err)
	}

	func() {
		for {
			buf := make([]byte, 1500)
			n, addr, err := p.conn.ReadFrom(buf)
			if n > 0 {
				p.l.Debugf("received %d bytes from %s", n, addr)

				err = p.handleRequest(addr, buf[0:n])
				if err != nil {
					p.l.With(zap.Error(err)).Errorf("failed to handle request from %s", addr)
					continue
				}

				continue
			} else if err != nil {
				p.l.With(zap.Error(err)).Errorf("failed to read")
				return
			}
		}
	}()
	return nil
}

func (p *PCPServer) handleRequest(addr net.Addr, buf []byte) error {
	if len(buf) >= 1 && buf[0] == 0 {
		// Version 0
		err := p.handleNATPMPRequest(addr, buf)
		return err
	}
	// Respond with Unsupported Version
	p.responseWithErrorResultCode(addr, 1)
	return fmt.Errorf("unsupported version")
}

func (p *PCPServer) handleNATPMPRequest(addr net.Addr, buf []byte) error {
	if len(buf) >= 2 {
		switch buf[1] {
		case 0:
			return p.handleNATPMPExternalAddressRequest(addr)
		case 1: // UDP mapping request
			return p.handleNATPMPMappingRequest(1, addr, buf[4:])
		case 2: // TCP mapping request
			return p.handleNATPMPMappingRequest(2, addr, buf[4:])
		default:
			// Respond with Unsupported opcode
			p.responseWithErrorResultCode(addr, 5)
			return fmt.Errorf("operation not implemented")
		}

	}
	// Respond with Unsupported opcode
	p.responseWithErrorResultCode(addr, 5)
	return nil
}

func (p *PCPServer) responseWithErrorResultCode(addr net.Addr, code uint16) {
	res := make([]byte, 8)
	sec := time.Now().Unix() - p.started.Unix()
	writeNetworkOrderUint16(res[2:4], code)
	writeNetworkOrderUint32(res[4:8], uint32(sec)) // Seconds Since Start of Epoch
	if p.conn != nil {
		p.conn.WriteTo(res, addr)
	}
}

func (p *PCPServer) handleNATPMPExternalAddressRequest(addr net.Addr) error {
	res := make([]byte, 12)
	res[1] = 128 + 0 // Response op code
	// 2 byte result code
	sec := time.Now().Unix() - p.started.Unix()
	writeNetworkOrderUint32(res[4:8], uint32(sec)) // Seconds Since Start of Epoch
	writeNetworkOrderIP(res[8:12], p.externalIP.To4())
	if p.conn != nil {
		_, err := p.conn.WriteTo(res, addr)
		return err
	}
	return nil
}
func (p *PCPServer) handleNATPMPMappingRequest(op byte, addr net.Addr, buf []byte) error {
	internalPort, buf := readNetworkOrderUint16(buf)
	externalPort, buf := readNetworkOrderUint16(buf)
	lifetime, buf := readNetworkOrderUint32(buf)
	p.l.Infof("received mapping request for internalPort %d, externalPort %d with lifetime %d", internalPort, externalPort, lifetime)

	var clientIP net.IP
	switch addr := addr.(type) {
	case *net.UDPAddr:
		clientIP = addr.IP
	case *net.TCPAddr:
		clientIP = addr.IP
	}

	var protocol PROTOCOL
	switch op {
	case 1:
		protocol = UDP
	case 2:
		protocol = TCP
	}

	// Check ACL
	allowed := p.allowDefault
	if p.acl != nil {
		p.l.Debugf("Checking ACL for request from %s for %d", clientIP.String(), internalPort)
		for _, a := range p.acl {
			_, ipNet, err := net.ParseCIDR(a.CIDR)
			if err != nil {
				p.l.With(zap.Error(err)).Warnf("failed to parse cidr %s", a.CIDR)
				continue
			}
			if ipNet.Contains(clientIP) && isPortInRange(internalPort, a.InternalPorts) {
				allowed = !a.Deny
				if allowed {
					break
				}
			}
		}
	}

	resultCode := 0
	if allowed {

		lease, err := p.store.GetLeaseByIpAndPort(clientIP, internalPort, protocol)
		if err != nil {
			return fmt.Errorf("error getting existing lease %v", err)
		}
		if lease == nil {
			start := uint16(10000)
			end := uint16(10999)
			externalPort = randomPort(start, end)
			for i := 0; i < 10; i++ {
				if !p.store.IsExternalPortInUse(externalPort) {
					break
				}
				if i == 9 {
					return fmt.Errorf("no port is free")
				}
				externalPort = randomPort(start, end)
			}

			lease = &PortMappingLease{
				Id:           leaseHash(protocol, clientIP, internalPort),
				Created:      time.Now(),
				LastSeen:     time.Now(),
				ClientIP:     clientIP,
				ClientPort:   internalPort,
				Protocol:     protocol,
				ExternalPort: externalPort,
			}
		}
		lease.LastSeen = time.Now()
		err = p.store.UpsertLease(lease)
		if err != nil {
			return fmt.Errorf("failed to upsert new lease %v", err)
		}
		externalPort = lease.ExternalPort

		for _, listener := range p.listeners {
			go listener(*lease)
		}

		p.ipt.Reconcile()

		p.l.Debugf("created mapping request for %s internalPort %d, externalPort %d with lifetime %d", clientIP.String(), internalPort, externalPort, lifetime)
	} else {
		p.l.Warnf("port-mapping is not allowed from %s for %d", clientIP.String(), internalPort)
		resultCode = 2
	}

	res := make([]byte, 16)
	res[1] = 128 + op // Response op code
	// 2 byte result code
	res[3] = byte(resultCode)
	sec := time.Now().Unix() - p.started.Unix()
	writeNetworkOrderUint32(res[4:8], uint32(sec)) // Seconds Since Start of Epoch
	writeNetworkOrderUint16(res[8:10], internalPort)
	writeNetworkOrderUint16(res[10:12], externalPort)
	writeNetworkOrderUint32(res[12:16], lifetime)
	if p.conn != nil {
		_, err := p.conn.WriteTo(res, addr)
		return err
	}
	return nil
}

func (p *PCPServer) Stop() error {
	if p.conn != nil {
		err := p.conn.Close()
		p.conn = nil
		return err
	}
	return nil
}

func (p *PCPServer) RegisterListener(fn func(lease PortMappingLease)) {
	p.listeners = append(p.listeners, fn)
}

func isPortInRange(port uint16, portRange string) bool {
	r := strings.Split(portRange, "-")
	start, err := strconv.Atoi(r[0])
	if err != nil {
		return false
	}
	end, err := strconv.Atoi(r[1])
	if err != nil {
		return false
	}
	return int(port) >= start && int(port) <= end
}

func writeNetworkOrderUint16(buf []byte, d uint16) {
	buf[0] = byte(d >> 8)
	buf[1] = byte(d)
}
func writeNetworkOrderUint32(buf []byte, d uint32) {
	buf[0] = byte(d >> 24)
	buf[1] = byte(d >> 16)
	buf[2] = byte(d >> 8)
	buf[3] = byte(d)
}
func writeNetworkOrderIP(buf []byte, d net.IP) {
	buf[0] = d[0]
	buf[1] = d[1]
	buf[2] = d[2]
	buf[3] = d[3]
}

func readNetworkOrderUint16(buf []byte) (uint16, []byte) {
	return (uint16(buf[0]) << 8) | uint16(buf[1]), buf[2:]
}

func readNetworkOrderUint32(buf []byte) (uint32, []byte) {
	return (uint32(buf[0]) << 24) | (uint32(buf[1]) << 16) | (uint32(buf[2]) << 8) | uint32(buf[3]), buf[4:]
}

func randomPort(start, end uint16) uint16 {
	size := end - start + 1
	return uint16(rand.Intn(int(size))) + start
}
