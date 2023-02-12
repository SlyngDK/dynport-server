module pcp-server

go 1.20

require (
	github.com/coreos/go-iptables v0.6.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/google/uuid v1.3.0
	github.com/jackpal/go-nat-pmp v1.0.2
	github.com/timshannon/badgerhold v1.0.0
	go.uber.org/zap v1.24.0
)

replace github.com/coreos/go-iptables => github.com/slyngdk/go-iptables v0.0.0-20230212184852-41950b3865a8

require (
	github.com/AndreasBriese/bbloom v0.0.0-20190825152654-46b345b51c96 // indirect
	github.com/dgraph-io/badger v1.6.0 // indirect
	github.com/dgryski/go-farm v0.0.0-20190423205320-6a90982ecee2 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/golang/protobuf v1.3.1 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/multierr v1.9.0 // indirect
	golang.org/x/net v0.0.0-20190620200207-3b0461eec859 // indirect
	golang.org/x/sys v0.0.0-20190626221950-04f50cda93cb // indirect
)
