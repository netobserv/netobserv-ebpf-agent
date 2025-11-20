package grpc

import (
	"time"

	"github.com/netobserv/loki-client-go/pkg/logproto"
	"github.com/prometheus/common/model"
)

// entry represents a log entry with tenant and label information
type entry struct {
	tenantID string
	labels   model.LabelSet
	logproto.Entry
}

// batch holds pending log streams waiting to be sent to Loki via GRPC.
// Similar to HTTP batch but optimized for GRPC operations.
type batch struct {
	streams   map[string]*logproto.Stream
	bytes     int
	createdAt time.Time
	tenantID  string // GRPC batches are per-tenant for connection management
}

// newBatch creates a new batch for a specific tenant
func newBatch(tenantID string, entries ...entry) *batch {
	b := &batch{
		streams:   map[string]*logproto.Stream{},
		bytes:     0,
		createdAt: time.Now(),
		tenantID:  tenantID,
	}

	// Add entries to the batch
	for _, entry := range entries {
		b.add(entry)
	}

	return b
}

// add an entry to the batch
func (b *batch) add(entry entry) {
	b.bytes += len(entry.Line)

	// Append the entry to an already existing stream (if any)
	labels := entry.labels.String()
	if stream, ok := b.streams[labels]; ok {
		stream.Entries = append(stream.Entries, entry.Entry)
		return
	}

	// Add the entry as a new stream
	b.streams[labels] = &logproto.Stream{
		Labels:  labels,
		Entries: []logproto.Entry{entry.Entry},
	}
}

// sizeBytes returns the current batch size in bytes
func (b *batch) sizeBytes() int {
	return b.bytes
}

// sizeBytesAfter returns the size of the batch after the input entry
// will be added to the batch itself
func (b *batch) sizeBytesAfter(entry entry) int {
	return b.bytes + len(entry.Line)
}

// age of the batch since its creation
func (b *batch) age() time.Duration {
	return time.Since(b.createdAt)
}

// createPushRequest creates a push request from the batch
func (b *batch) createPushRequest() (*logproto.PushRequest, int) {
	req := &logproto.PushRequest{
		Streams: make([]logproto.Stream, 0, len(b.streams)),
	}

	entriesCount := 0
	for _, stream := range b.streams {
		req.Streams = append(req.Streams, *stream)
		entriesCount += len(stream.Entries)
	}

	return req, entriesCount
}

// isEmpty returns true if the batch has no entries
func (b *batch) isEmpty() bool {
	return len(b.streams) == 0
}

// streamCount returns the number of streams in the batch
func (b *batch) streamCount() int {
	return len(b.streams)
}

// entryCount returns the total number of entries across all streams
func (b *batch) entryCount() int {
	count := 0
	for _, stream := range b.streams {
		count += len(stream.Entries)
	}
	return count
}
