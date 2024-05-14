package observability_lib

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
	"strings"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

const (
	PSAMPLE_GENL_NAME            = "psample"
	PSAMPLE_NL_MCGRP_SAMPLE_NAME = "packets"
)

const (
	PSAMPLE_ATTR_IIFINDEX = iota
	PSAMPLE_ATTR_OIFINDEX
	PSAMPLE_ATTR_ORIGSIZE
	PSAMPLE_ATTR_SAMPLE_GROUP
	PSAMPLE_ATTR_GROUP_SEQ
	PSAMPLE_ATTR_SAMPLE_RATE
	PSAMPLE_ATTR_DATA
	PSAMPLE_ATTR_GROUP_REFCOUNT
	PSAMPLE_ATTR_TUNNEL

	PSAMPLE_ATTR_PAD
	PSAMPLE_ATTR_OUT_TC     /* u16 */
	PSAMPLE_ATTR_OUT_TC_OCC /* u64, bytes */
	PSAMPLE_ATTR_LATENCY    /* u64, nanoseconds */
	PSAMPLE_ATTR_TIMESTAMP  /* u64, nanoseconds */
	PSAMPLE_ATTR_PROTO      /* u16 */
	PSAMPLE_ATTR_USER_COOKIE

	__PSAMPLE_ATTR_MAX
)

func parseMsg(msgs []syscall.NetlinkMessage, decoder *SampleDecoder) error {
	for _, msg := range msgs {
		res := make([]string, 3)
		data := msg.Data[nl.SizeofGenlmsg:]
		for attr := range nl.ParseAttributes(data) {
			if attr.Type == PSAMPLE_ATTR_SAMPLE_GROUP {
				if uint64(len(attr.Value)) == 4 {
					g := uint32(0)
					err := binary.Read(bytes.NewReader(attr.Value), nativeEndian, &g)
					if err != nil {
						return err
					}
					res[0] = fmt.Sprintf("group_id %v", g)
				}
			}
			if attr.Type == PSAMPLE_ATTR_USER_COOKIE {
				if uint64(len(attr.Value)) == cookieSize {
					c := Cookie{}
					err := binary.Read(bytes.NewReader(attr.Value), nativeEndian, &c)
					if err != nil {
						return err
					}
					res[1] = fmt.Sprintf("obs_domain=%v, obs_point=%v", c.ObsDomainID, c.ObsPointID)
					if decoder != nil {
						decoded, err := decoder.DecodeCookieIDs(c.ObsDomainID, c.ObsPointID)
						if err != nil {
							fmt.Println("Failed decoding:", err)
						} else {
							fmt.Println("OVN-K message:", decoded)
						}
					}
				}
			}
			if attr.Type == PSAMPLE_ATTR_DATA {
				packet := gopacket.NewPacket(attr.Value, layers.LayerTypeEthernet, gopacket.Default)
				res[2] = fmt.Sprintf("%+v", packet)
			}
		}
		fmt.Println(strings.Join(res, ", "))
	}
	return nil
}

func ReadSamples(ctx context.Context, enableDecoder bool) error {
	setEndian()

	var decoder *SampleDecoder
	if enableDecoder {
		var err error
		decoder, err = NewSampleDecoder(ctx)
		if err != nil {
			return fmt.Errorf("error creating decoder: %w", err)
		}
	}

	f, err := netlink.GenlFamilyGet(PSAMPLE_GENL_NAME)
	if err != nil {
		return err
	}
	if len(f.Groups) == 0 {
		return fmt.Errorf("No mcast groups found for %s", PSAMPLE_GENL_NAME)
	}
	var ovsGroupID uint32
	for _, group := range f.Groups {
		if group.Name == PSAMPLE_NL_MCGRP_SAMPLE_NAME {
			ovsGroupID = group.ID
		}
	}
	if ovsGroupID == 0 {
		return fmt.Errorf("No mcast group found for %s", PSAMPLE_NL_MCGRP_SAMPLE_NAME)
	} else {
		fmt.Printf("Found group %s, id %d\n", PSAMPLE_NL_MCGRP_SAMPLE_NAME, ovsGroupID)
	}
	sock, err := nl.Subscribe(nl.GENL_ID_CTRL, uint(ovsGroupID))
	if err != nil {
		return err
	}

	// Otherwise sock.Receive() will be blocking and won't return on context close
	if err = unix.SetNonblock(sock.GetFd(), true); err != nil {
		return err
	}
	//if err := sock.SetNetlinkOption(unix.NETLINK_LISTEN_ALL_NSID, 1); err != nil {
	//	return err
	//}

	defer func() {
		sock.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			msgs, _, err := sock.Receive()
			if err != nil {
				if err == syscall.EAGAIN {
					continue
				}
				return fmt.Errorf("receive failed: %w", err)
			}
			if err = parseMsg(msgs, decoder); err != nil {
				fmt.Println("ERROR", err)
			}
		}
	}
}
