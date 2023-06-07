package xdpnatforward

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"fmt"
	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/google/gopacket/routing"
	"github.com/vishvananda/netlink"
	"net"
	"strconv"
	"strings"
)

// go generate requires appropriate linux headers in included (-I) paths.
// See accompanying Makefile + Dockerfile to make updates.
//go:generate $HOME/go/bin/bpf2go natforward nat_forward.c -- -I/usr/include/ -I./include -nostdinc -O3

type XDPProgram struct {
	Program *xdp.Program
	Objs    *natforwardMaps
}

func (x *XDPProgram) Close() {
	if x.Program != nil {
		x.Program.Close()
	}
	if x.Objs != nil {
		x.Objs.Close()
	}
}

func LoadNatForward(options *ebpf.CollectionOptions) (*XDPProgram, error) {
	spec, err := loadNatforward()
	if err != nil {
		return nil, err
	}

	var program natforwardObjects
	if err := spec.LoadAndAssign(&program, options); err != nil {
		return nil, err
	}

	p := &xdp.Program{Program: program.XdpNatForward}
	return &XDPProgram{p, &program.natforwardMaps}, nil
}

func NewDestination(ifindex int32, dmac, smac uint64, ip net.IP, port uint16) (*natforwardRemappingMap, error) {

	iip, err := IPv4ToInt(ip)
	if err != nil {
		return nil, err
	}

	return &natforwardRemappingMap{
		Ifindex: ifindex,
		Dmac:    dmac,
		Smac:    smac,
		Ip:      iip,
		Port:    port,
	}, nil
}

// Assert that customEncoding implements the correct interfaces.
var (
	_ encoding.BinaryMarshaler = (*natforwardRemappingMap)(nil)
)

func (ce *natforwardRemappingMap) MarshalBinary() ([]byte, error) {
	var wr bytes.Buffer
	err := binary.Write(&wr, NativeEndian, ce.Ifindex)
	if err != nil {
		err = fmt.Errorf("encoding %T: %v", ce.Ifindex, err)
	}

	binary.Write(&wr, NativeEndian, make([]byte, 2))

	err = binary.Write(&wr, binary.BigEndian, ce.Smac)
	if err != nil {
		err = fmt.Errorf("encoding %T: %v", ce.Smac, err)
	}
	err = binary.Write(&wr, binary.BigEndian, ce.Dmac)
	if err != nil {
		err = fmt.Errorf("encoding %T: %v", ce.Dmac, err)
	}
	binary.Write(&wr, NativeEndian, make([]byte, 2))
	err = binary.Write(&wr, binary.BigEndian, ce.Ip)
	if err != nil {
		err = fmt.Errorf("encoding %T: %v", ce.Ip, err)
	}

	err = binary.Write(&wr, binary.BigEndian, ce.Port)
	if err != nil {
		err = fmt.Errorf("encoding %T: %v", ce.Port, err)
	}

	binary.Write(&wr, NativeEndian, make([]byte, 2))

	return wr.Bytes(), nil
}

type Stats struct {
	Processed   uint64
	Source      uint64
	Destination uint64
	Redirect    uint64
}

func (n *natforwardMaps) GetStats() Stats {
	s := Stats{}
	_ = n.RxCnt.Lookup([]byte{0}, &s.Processed)
	_ = n.RxCnt.Lookup([]byte{1}, &s.Source)
	_ = n.RxCnt.Lookup([]byte{3}, &s.Destination)
	_ = n.RxCnt.Lookup([]byte{2}, &s.Redirect)
	return s
}

type Mapping struct {
	PublicIP    net.IP
	PublicPort  uint16
	PrivateIP   net.IP
	PrivatePort uint16
}

func GetSource(m Mapping) ([]byte, *natforwardRemappingMap, error) {
	key, err := getKey(m.PrivateIP, m.PrivatePort)
	if err != nil {
		return nil, nil, err
	}

	router, err := routing.New()
	if err != nil {
		return nil, nil, err
	}

	iface, _, _, err := router.Route(m.PublicIP)
	if err != nil {
		return nil, nil, err
	}
	_, gateway, _, err := router.Route(net.ParseIP("1.1.1.1"))
	if err != nil {
		return nil, nil, err
	}

	var smac, dmac uint64

	neighs, err := netlink.NeighList(iface.Index, netlink.FAMILY_V4)
	if err != nil {
		return nil, nil, err
	}
	for _, neigh := range neighs {
		if neigh.IP.Equal(gateway) {
			dmac, err = strconv.ParseUint(strings.ReplaceAll(neigh.HardwareAddr.String(), ":", ""), 16, 64)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	smac, err = strconv.ParseUint(strings.ReplaceAll(iface.HardwareAddr.String(), ":", ""), 16, 64)
	if err != nil {
		return nil, nil, err
	}

	value, err := NewDestination(int32(iface.Index), dmac, smac, m.PublicIP, m.PublicPort)
	if err != nil {
		return nil, nil, err
	}

	return key, value, nil
}

func GetDestination(m Mapping) ([]byte, *natforwardRemappingMap, error) {
	key, err := getKey(m.PublicIP, m.PublicPort)
	if err != nil {
		return nil, nil, err
	}

	router, err := routing.New()
	if err != nil {
		return nil, nil, err
	}

	iface, _, _, err := router.Route(m.PrivateIP)
	if err != nil {
		return nil, nil, err
	}

	var smac, dmac uint64

	neighs, err := netlink.NeighList(iface.Index, netlink.FAMILY_V4)
	if err != nil {
		return nil, nil, err
	}
	for _, neigh := range neighs {
		if neigh.IP.Equal(m.PrivateIP) {
			dmac, err = strconv.ParseUint(strings.ReplaceAll(neigh.HardwareAddr.String(), ":", ""), 16, 64)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	smac, err = strconv.ParseUint(strings.ReplaceAll(iface.HardwareAddr.String(), ":", ""), 16, 64)
	if err != nil {
		return nil, nil, err
	}

	value, err := NewDestination(int32(iface.Index), dmac, smac, m.PrivateIP, m.PrivatePort)
	if err != nil {
		return nil, nil, err
	}

	return key, value, nil
}

func getKey(ip net.IP, port uint16) ([]byte, error) {
	var wr bytes.Buffer
	sip, err := IPv4ToInt(ip)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&wr, binary.BigEndian, sip)
	if err != nil {
		return nil, fmt.Errorf("encoding %T: %v", sip, err)
	}
	err = binary.Write(&wr, binary.BigEndian, port)
	if err != nil {
		return nil, fmt.Errorf("encoding %T: %v", port, err)
	}

	return wr.Bytes(), nil
}

func IPv4ToInt(ipaddr net.IP) (uint32, error) {
	if ipaddr.To4() == nil {
		return 0, fmt.Errorf("not an IPv4 addres")
	}
	return binary.BigEndian.Uint32(ipaddr.To4()), nil
}
