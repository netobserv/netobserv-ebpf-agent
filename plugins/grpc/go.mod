module github.com/netobserv/netobserv-ebpf-agent/plugins/exporter/grpc

go 1.18

require (
	github.com/netobserv/netobserv-ebpf-agent v0.0.0
	github.com/sirupsen/logrus v1.9.0
)

require (
	github.com/cilium/ebpf v0.8.1 // indirect
	github.com/gavv/monotime v0.0.0-20190418164738-30dba4353424 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/netobserv/gopipes v0.2.0 // indirect
	github.com/vishvananda/netlink v1.1.0 // indirect
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df // indirect
	golang.org/x/net v0.0.0-20220706163947-c90051bbdb60 // indirect
	golang.org/x/sys v0.2.0 // indirect
	golang.org/x/text v0.3.7 // indirect
	google.golang.org/genproto v0.0.0-20220407144326-9054f6ed7bac // indirect
	google.golang.org/grpc v1.45.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
)

replace github.com/netobserv/netobserv-ebpf-agent v0.0.0 => ../..
// avoid annoying error: "plugin was built with a different version of package golang.org/x/sys/unix"
replace golang.org/x/sys v0.2.0 => ../../fix-vendor/xsys