//go:build armbe || arm64be || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64
// +build armbe arm64be mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

package xdpnatforward

import "encoding/binary"

// NativeEndian is set to either binary.BigEndian or binary.LittleEndian,
// depending on the host's endianness.
var NativeEndian binary.ByteOrder = binary.BigEndian
