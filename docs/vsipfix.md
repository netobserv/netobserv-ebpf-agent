# eBPF-based vs OVS IPFIX-based flows

OVS and IPFIX provide a set of fields that are not yet addressed in this flow collector.
More info on fields at:
* https://www.ietf.org/rfc/rfc3954.txt
* https://www.iana.org/assignments/ipfix/ipfix.xhtml
* https://github.com/netsampler/goflow2/blob/main/docs/protocols.md

| Field             | Supported | 
|-------------------|:---------:|
| FlowDirection     |    ✅️     |  
| BiFlowDirection   |     ❌     | 
| Bytes             |     ✅     | 
| SrcAS             |     ❌     |    
| DstAS             |     ❌     | 
| SrcAddr [1]       |     ✅     | 
| DstAddr [1]       |     ✅     | 
| SrcMac            |     ✅     | 
| DstMac            |     ✅     | 
| SrcNet            |     ❌     |    
| DstNet            |     ❌     | 
| SrcPort           |     ✅     | 
| DstPort           |     ✅     | 
| SrcVlan           |     ❌     |    
| DstVlan           |     ❌     | 
| EgressVrfID       |     ❌     | 
| IngressVrfID      |     ❌     | 
| Etype             |     ✅     |     
| ForwardingStatus  |     ❌     | 
| FragmentOffset    |     ❌     | 
| HasMPLS           |     ❌     | 
| IPTTL             |     ❌     | 
| IPTos             |     ❌     | 
| IPv6FlowLabel     |     ❌     | 
| IcmpCode          |     ❌     | 
| IcmpType          |     ❌     | 
| InIf              |     ❌     | 
| OutIf             |     ❌     | 
| MPLSxLabel        |     ❌     | 
| MPLSxTTL          |     ❌     | 
| MPLSCount         |     ❌     | 
| MPLSLastLabel     |     ❌     | 
| MPLSLastTTL       |     ❌     | 
| NextHop           |     ❌     | 
| NextHopAS         |     ❌     | 
| Packets           |     ✅     | 
| Proto [2]         |     ✅     | 
| SamplerAddress    |     ❌     | 
| SamplingRate      |     ❌     | 
| SequenceNum       |     ❌     | 
| TCPFlags          |     ❌     | 
| TimeFlowStart [3] |     ✅     | 
| TimeFlowEnd [3]   |     ✅     | 
| VlanId            |     ❌     |      

[1] Currently only supporting IPv4
[2] https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
[3] We had seconds precision and now we will have milliseconds precision.


Fields that are added in this Agent:

* `Interface` containing the network interface name


IPFIX flow (enriched), used as reference:
```json
{
  "BiFlowDirection": 0,
  "Bytes": 9200,
  "CustomBytes1": null,
  "CustomBytes2": null,
  "CustomInteger1": 0,
  "CustomInteger2": 0,
  "DstAS": 0,
  "DstAddr": "10.130.0.11",
  "DstHostIP": "10.0.154.50",
  "DstMac": "0a:58:0a:81:00:01",
  "DstNamespace": "openshift-network-diagnostics",
  "DstNet": 0,
  "DstPod": "network-check-source-865d4b5578-pvhkm",
  "DstPort": 17698,
  "DstVlan": 0,
  "DstWorkload": "network-check-source",
  "DstWorkloadKind": "Deployment",
  "EgressVrfID": 0,
  "Etype": 2048,
  "FlowDirection": 0,
  "ForwardingStatus": 0,
  "FragmentId": 0,
  "FragmentOffset": 0,
  "HasMPLS": false,
  "IPTTL": 0,
  "IPTos": 0,
  "IPv6FlowLabel": 0,
  "IcmpCode": 0,
  "IcmpType": 0,
  "InIf": 15,
  "IngressVrfID": 0,
  "MPLS1Label": 0,
  "MPLS1TTL": 0,
  "MPLS2Label": 0,
  "MPLS2TTL": 0,
  "MPLS3Label": 0,
  "MPLS3TTL": 0,
  "MPLSCount": 0,
  "MPLSLastLabel": 0,
  "MPLSLastTTL": 0,
  "NextHop": null,
  "NextHopAS": 0,
  "OutIf": 0,
  "Packets": 100,
  "Proto": 6,
  "SamplerAddress": "ZEAAAw==",
  "SamplingRate": 0,
  "SequenceNum": 43,
  "SrcAS": 0,
  "SrcAddr": "10.129.0.7",
  "SrcHostIP": "10.0.164.230",
  "SrcMac": "0a:58:0a:81:00:07",
  "SrcNamespace": "openshift-monitoring",
  "SrcNet": 0,
  "SrcPod": "prometheus-k8s-0",
  "SrcPort": 57240,
  "SrcVlan": 0,
  "SrcWorkload": "prometheus-k8s",
  "SrcWorkloadKind": "StatefulSet",
  "TCPFlags": 0,
  "TimeFlowEnd": 1647426199,
  "TimeFlowStart": 1647426199,
  "TimeReceived": 1647426258,
  "Type": 4,
  "VlanId": 0
}
```

eBPF flow example:

```json
{
  "Etype": 8,
  "Direction": "EGRESS",
  "DataLink": {
    "SrcMac": "08:00:27:23:e8:8a",
    "DstMac": "52:54:00:12:35:02"
  },
  "Network": {
    "SrcAddr": "10.0.2.15",
    "DstAddr": "10.0.2.2"
  },
  "Transport": {
    "SrcPort": 22,
    "DstPort": 51819,
    "Proto": "TCP"
  },
  "Bytes": 56320,
  "TimeFlowStart": "2022-03-17T07:42:12.414480074Z",
  "TimeFlowEnd": "2022-03-17T07:42:12.414849771Z",
  "Interface": "eth0",
  "Packets": 2
}
```