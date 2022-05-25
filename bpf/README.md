##Flows v2. A Flow-metric generator using TC.

This program can be hooked on to TC ingress/egress hook to monitor packets
to/from an interface.

### Logic:
    1) Store flow information in a per-cpu hash map.
    2) Upon flow completion (tcp->fin event), evict the entry from map, and
       send to userspace through ringbuffer.
       Eviction for non-tcp flows need to done by userspace
    3) When the map is full, we have two choices:
            1) Send the new flow entry to userspace via ringbuffer,
                    until an entry is available.
            2) Send an existing flow entry (probably least recently used)
                    to userspace via ringbuffer, delete that entry, and add in the
                    new flow to the hash map.

            Ofcourse, 2nd step involves more manipulations and
                state maintenance, and question is will it provide any performance benefit?
