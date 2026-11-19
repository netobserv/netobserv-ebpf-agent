package flows

import (
	"context"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pb/flow"

	kafkago "github.com/segmentio/kafka-go"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

var klog = logrus.WithField("component", "exporter/KafkaProto")

const componentKafka = "kafka"

type kafkaWriter interface {
	WriteMessages(ctx context.Context, msgs ...kafkago.Message) error
}

// KafkaProto exports flows over Kafka, encoded as a protobuf that is understandable by the
// Flowlogs-Pipeline collector
type KafkaProto struct {
	Writer        kafkaWriter
	Metrics       *metrics.Metrics
	Async         bool
	QueueCapacity int
}

func (kp *KafkaProto) ExportFlows(input <-chan *model.FlowBatch) {
	klog.Info("starting Kafka exporter")
	if kp.Async {
		kp.exportFlowsAsync(input)
		return
	}
	for batch := range input {
		kp.batchAndSubmit(batch.Records)
		batch.Release()
	}
}

// exportFlowsAsync keeps asynchronous handoff inside the agent's byte budget.
// The worker uses synchronous Kafka writes and releases each batch only after
// WriteMessages returns. The queue has a finite capacity; if it fills, reading
// from the upstream exporter channel pauses and the shared limiter rejects new
// batches instead of allowing Kafka's internal async queue to grow unbounded.
func (kp *KafkaProto) exportFlowsAsync(input <-chan *model.FlowBatch) {
	queueCapacity := kp.QueueCapacity
	if queueCapacity < 1 {
		queueCapacity = 1
	}
	queue := make(chan *model.FlowBatch, queueCapacity)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		for batch := range queue {
			kp.batchAndSubmit(batch.Records)
			batch.Release()
		}
	}()
	for batch := range input {
		queue <- batch
	}
	close(queue)
	<-workerDone
}

func getFlowKey(record *model.Record) []byte {
	// We are sorting IP address so flows from on ip to a second IP get the same key whatever the direction is
	for k := range record.ID.SrcIp {
		if record.ID.SrcIp[k] < record.ID.DstIp[k] {
			return append(record.ID.SrcIp[:], record.ID.DstIp[:]...)
		} else if record.ID.SrcIp[k] > record.ID.DstIp[k] {
			return append(record.ID.DstIp[:], record.ID.SrcIp[:]...)
		}
	}
	return append(record.ID.SrcIp[:], record.ID.DstIp[:]...)
}

func (kp *KafkaProto) batchAndSubmit(records []*model.Record) {
	klog.Debugf("sending %d records", len(records))
	msgs := make([]kafkago.Message, 0, len(records))
	for _, record := range records {
		pbBytes, err := proto.Marshal(pbflow.FlowToPB(record))
		if err != nil {
			klog.WithError(err).Debug("can't encode protobuf message. Ignoring")
			kp.Metrics.Errors.WithErrorName(componentKafka, "CannotEncodeMessage", metrics.HighSeverity).Inc()
			continue
		}
		msgs = append(msgs, kafkago.Message{Value: pbBytes, Key: getFlowKey(record)})
	}

	if err := kp.Writer.WriteMessages(context.TODO(), msgs...); err != nil {
		klog.WithError(err).Error("can't write messages into Kafka")
		kp.Metrics.Errors.WithErrorName(componentKafka, "CannotWriteMessage", metrics.HighSeverity).Inc()
	}
	kp.Metrics.EvictionCounter.WithSource(componentKafka).Inc()
	kp.Metrics.EvictedFlowsCounter.WithSource(componentKafka).Add(float64(len(records)))
}

type JSONRecord struct {
	*model.Record
	TimeFlowStart   int64
	TimeFlowEnd     int64
	TimeFlowStartMs int64
	TimeFlowEndMs   int64
}
