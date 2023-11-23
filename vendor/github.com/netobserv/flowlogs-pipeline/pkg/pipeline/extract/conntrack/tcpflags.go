/*
 * Copyright (C) 2023 IBM, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package conntrack

// From: https://github.com/netobserv/netobserv-ebpf-agent/blob/c54e7eb9e37e8ef5bb948eff6141cdddf584a6f9/bpf/flows.c#L45-L56
const (
	FIN_FLAG = uint32(0x01)
	SYN_FLAG = uint32(0x02)
	RST_FLAG = uint32(0x04)
	PSH_FLAG = uint32(0x08)
	ACK_FLAG = uint32(0x10)
	URG_FLAG = uint32(0x20)
	ECE_FLAG = uint32(0x40)
	CWR_FLAG = uint32(0x80)
	// Custom flags
	SYN_ACK_FLAG = uint32(0x100)
	FIN_ACK_FLAG = uint32(0x200)
	RST_ACK_FLAG = uint32(0x400)
	// Note: The difference between SYN_FLAG | ACK_FLAG (0x12) and SYN_ACK_FLAG (0x100) is that the former indicates
	// that a flowlog contains TCP packets with the SYN flag set and the ACK flag set, but not necessary in the same packet.
	// While the latter indicates that a flowlog contains a TCP packet with both flags set.
)
