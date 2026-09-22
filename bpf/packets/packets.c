#include <vmlinux.h>
#include <bpf_helpers.h>
#include "../types.h"
#include "packet_capture.h"
#include "../openssl_tracker.h"

char _license[] SEC("license") = "GPL";
