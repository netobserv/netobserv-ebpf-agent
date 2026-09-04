package plaintext

import (
	"encoding/base64"
	"time"

	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
)

// ToMap converts a PlaintextRecord to a GenericMap for FLP export.
func ToMap(pr *model.PlaintextRecord, previewBytes int) config.GenericMap {
	out := config.GenericMap{}

	if pr == nil {
		return out
	}

	out["RecordType"] = "plaintext"
	out["Time"] = float64(pr.Timestamp.Unix())
	out["TimeFlowStartMs"] = pr.Timestamp.UnixMilli()
	out["Pid"] = pr.Pid
	out["Tgid"] = pr.Tgid
	out["Plaintext"] = base64.StdEncoding.EncodeToString(pr.Data)
	out["PlaintextLen"] = len(pr.Data)
	out["Direction"] = pr.Direction
	out["TLSSource"] = pr.TLSSource
	out["SSLType"] = pr.SSLType
	if pr.SrcAddr != "" {
		out["SrcAddr"] = pr.SrcAddr
	}
	if pr.DstAddr != "" {
		out["DstAddr"] = pr.DstAddr
	}
	if pr.SrcPort > 0 {
		out["SrcPort"] = pr.SrcPort
	}
	if pr.DstPort > 0 {
		out["DstPort"] = pr.DstPort
	}
	if pr.Protocol != "" {
		out["Protocol"] = pr.Protocol
	}

	if n := PreviewLength(previewBytes, len(pr.Data)); n > 0 {
		out["PlaintextPreview"] = string(pr.Data[:n])
	}

	return out
}

// IsPlaintextRecord returns true if the map is a TLS plaintext event.
func IsPlaintextRecord(m config.GenericMap) bool {
	rt, ok := m["RecordType"].(string)
	return ok && rt == "plaintext"
}

// Time returns the event timestamp from a plaintext GenericMap record.
func Time(m config.GenericMap) time.Time {
	if t, ok := m["Time"].(float64); ok {
		return time.Unix(int64(t), 0)
	}
	return time.Time{}
}
