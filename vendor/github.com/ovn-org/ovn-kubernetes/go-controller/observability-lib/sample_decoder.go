package observability_lib

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/ovn-org/libovsdb/client"
	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
)

type SampleDecoder struct {
	nbClient client.Client
}

type nbConfig struct {
	address string
	scheme  string
}

type Cookie struct {
	ObsDomainID uint32
	ObsPointID  uint32
}

const cookieSize = 8

var nativeEndian binary.ByteOrder

func setEndian() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}
	fmt.Printf("Endian is %v\n", nativeEndian)
}

func NewSampleDecoder(ctx context.Context) (*SampleDecoder, error) {
	setEndian()
	config := nbConfig{
		address: "unix:/var/run/ovn/ovnnb_db.sock",
		scheme:  "unix",
	}
	libovsdbOvnNBClient, err := NewNBClientWithConfig(ctx, config)

	if err != nil {
		return nil, fmt.Errorf("error creating libovsdb client: %w", err)
	}

	return &SampleDecoder{
		nbClient: libovsdbOvnNBClient,
	}, nil
}

func (d *SampleDecoder) DecodeCookieIDs(obsDomainID, obsPointID uint32) (string, error) {
	// assume any domain ID means ACL
	// assume point ID means any
	acls, err := libovsdbops.FindACLsWithPredicate(d.nbClient, func(acl *nbdb.ACL) bool {
		return true
	})
	if err != nil {
		return "", fmt.Errorf("nbdb get failed: %w", err)
	}
	if len(acls) == 0 {
		return "", fmt.Errorf("no ACLs found")
	}
	return acls[0].UUID, nil
}

func (d *SampleDecoder) DecodeCookieBytes(cookie []byte) (string, error) {
	if uint64(len(cookie)) != cookieSize {
		return "", fmt.Errorf("invalid cookie size: %d", len(cookie))
	}
	c := Cookie{}
	err := binary.Read(bytes.NewReader(cookie), nativeEndian, &c)
	if err != nil {
		return "", err
	}
	return d.DecodeCookieIDs(c.ObsDomainID, c.ObsPointID)
}

func (d *SampleDecoder) DecodeCookie8Bytes(cookie [8]byte) (string, error) {
	c := Cookie{}
	err := binary.Read(bytes.NewReader(cookie[:]), nativeEndian, &c)
	if err != nil {
		return "", err
	}
	return d.DecodeCookieIDs(c.ObsDomainID, c.ObsPointID)
}
