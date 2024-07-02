An example program that uses the observability library to decode and print samples can be found in
[ovnkubeobserv.go](../cmd/ovnkube-observ/ovnkubeobserv.go). The compiled binary for this program is 15 MB.
To get the binary, run 
```shell
hack/build-go.sh cmd/ovnkube-observ
```
The binary will be created under `./_output/go/bin`.

## OVS test setup
```shell
/usr/share/openvswitch/scripts/ovs-ctl start
ovs-vsctl add-br test
ip netns add ns1
ip netns add ns2
ip link add p1r type veth peer name p1l
ip link add p2r type veth peer name p2l
ip link set p1r netns ns1
ip link set p2r netns ns2
ip netns exec ns1 sh -c "ip link set dev p1r up && ip add add 10.0.0.1/24 dev p1r"
ip netns exec ns2 sh -c "ip link set dev p2r up && ip add add 10.0.0.2/24 dev p2r"
ip link set p1l up && ovs-vsctl add-port test p1l
ip link set p2l up && ovs-vsctl add-port test p2l

ovs-ofctl del-flows test
ovs-ofctl add-flows test - <<EOF
arp action=NORMAL
in_port=p1l actions=sample(probability=65535,collector_set_id=1,obs_domain_id=1,obs_point_id=1),NORMAL
in_port=p2l actions=sample(probability=65535,collector_set_id=1,obs_domain_id=1,obs_point_id=2),NORMAL
EOF

# Configure raw sampling
ovs-vsctl --id=@br get Bridge test -- create FLow_Sample_Collector_Set bridge=@br id=1 psample_group=10

# Now, generate some traffic
ip netns exec ns1 ping 10.0.0.2
```

### Extra setup steps on a bare RHEL node for observability-lib testing
```shell
# get some rhel9 ovn releaser, e.g. from https://brewweb.engineering.redhat.com/brew/buildinfo?buildID=3026196
dnf install ovn23.06-23.06.3-36.el9fdp.x86_64.rpm ovn23.06-central-23.06.3-36.el9fdp.x86_64.rpm

sudo mkdir -p /etc/ovn /var/run/ovn /var/log/ovn
sudo ovsdb-tool create /etc/ovn/ovnnb_db.db /usr/share/ovn/ovn-nb.ovsschema

sudo ovsdb-server /etc/ovn/ovnnb_db.db --remote=punix:/var/run/ovn/ovnnb_db.sock \
     --remote=db:OVN_Northbound,NB_Global,connections \
     --private-key=db:OVN_Northbound,SSL,private_key \
     --certificate=db:OVN_Northbound,SSL,certificate \
     --bootstrap-ca-cert=db:OVN_Northbound,SSL,ca_cert \
     --pidfile=/var/run/ovn/ovnnb-server.pid --detach --log-file=/var/log/ovn/ovnnb-server.log

ovn-nbctl show # should just succeed without any output and errors
ovn-nbctl ls-add test
ovn-nbctl --name="nice sample!" acl-add test to-lport 1001 "ip4.src == 1.1.1.1" drop
```

The expected "decoded" message from this setup is "nice sample!", you can check it if you run `ovnkube-observ` binary
with `-enable-enrichment` flag.

### Extra setup steps on an OCP node for observability-lib testing
Mount host `/var/run/ovn-ic` (since OCP 4.14) into your container under `/var/run/ovn`. 
The library should be able to connect to the nbdb now.