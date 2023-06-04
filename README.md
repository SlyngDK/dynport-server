# Dynamic Port Forward Server

This is a simple server receiving nat-pmp request for opening/forwarding ports in iptables. There is support for replication of leases between servers, when running HA firewall, and want the samme rules on both servers.

## Usage
```bash
Usage:
  dynport-server [flags]

Flags:
      --acl-allow-default                default allow port mappings
  -c, --config string                    config file (default "config.yaml")
      --create-chains                    create required chains (default true)
  -d, --data-dir string                  director to use for storing data (default "/tmp/dynport")
      --ebpf-enabled                     use ebpf/xdp to bypass iptables
      --external-ip string               ip to report to client as external (default auto detect)
  -h, --help                             help for dynport-server
      --listen-addrs strings             addresses to listen on for nat-pmp requests, needs to be actual ip
      --log-format string                log format (plain/json) (default "json")
      --log-level string                 log level (default "INFO")
      --port-range string                external port range to allocate from (default "10000-19999")
      --replication-listen-addr string   enable and listen for replication requests
      --replication-peers x.x.x.x:8080   peers to replicate with x.x.x.x:8080
      --skip-jump-check                  disable check of rule pointing to chains
```
