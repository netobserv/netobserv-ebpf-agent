# Performance testing

How to test your setup performance:

```
$ oc apply -f deployment.yml
$ oc get pods
NAME                              READY   STATUS    RESTARTS   AGE
netobserv-ebpf-agent              1/1     Running   0          20s
packet-counter-7b6df8b766-dbv8d   1/1     Running   0          20s
$ oc logs -f packet-counter-7b6df8b766-dbv8d
```

In the Packet Counter logs, you will see the rate of received packets and flows:

```
2022/03/23 13:24:32 615.6 packets/s. 13.6 flows/s
```

To generate network packets, you can deploy the `perftest-millionp.yml` deployment file:

```
$ oc apply -f perftest-millionp.yml
```

You can adjust the number of replicas in the `perftest-millionp.yml` file, to add more/less load.

* `perftest-millionp.yml` is able to provide a high sustained rate of packets
* `perftest-iperf.yml` generates a higher throughtput (GB/s) but the number of packets is lower
  and less stable.