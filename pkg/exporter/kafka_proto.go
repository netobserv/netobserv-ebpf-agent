package exporter

import (
	"context"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"

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
	Writer  kafkaWriter
	Metrics *metrics.Metrics
}

func (kp *KafkaProto) ExportFlows(input <-chan []*flow.Record) {
	klog.Info("starting Kafka exporter")
	for records := range input {
		kp.batchAndSubmit(records)
	}
}

func getFlowKey(record *flow.Record) []byte {
	// We are sorting IP address so flows from on ip to a second IP get the same key whatever the direction is
	for k := range record.Id.SrcIp {
		if record.Id.SrcIp[k] < record.Id.DstIp[k] {
			return append(record.Id.SrcIp[:], record.Id.DstIp[:]...)
		} else if record.Id.SrcIp[k] > record.Id.DstIp[k] {
			return append(record.Id.DstIp[:], record.Id.SrcIp[:]...)
		}
	}
	return append(record.Id.SrcIp[:], record.Id.DstIp[:]...)
}

func (kp *KafkaProto) batchAndSubmit(records []*flow.Record) {
	klog.Debugf("sending %d records", len(records))
	msgs := make([]kafkago.Message, 0, len(records))
	for _, record := range records {
		pbBytes, err := proto.Marshal(pbflow.FlowToPB(record))
		if err != nil {
			klog.WithError(err).Debug("can't encode protobuf message. Ignoring")
			kp.Metrics.Errors.WithErrorName(componentKafka, "CannotEncodeMessage").Inc()
			continue
		}
		msgs = append(msgs, kafkago.Message{Value: pbBytes, Key: getFlowKey(record)})
	}

	if err := kp.Writer.WriteMessages(context.TODO(), msgs...); err != nil {
		klog.WithError(err).Error("can't write messages into Kafka")
		kp.Metrics.Errors.WithErrorName(componentKafka, "CannotWriteMessage").Inc()
	}
	kp.Metrics.EvictionCounter.WithSource(componentKafka).Inc()
	kp.Metrics.EvictedFlowsCounter.WithSource(componentKafka).Add(float64(len(records)))
}

type JSONRecord struct {
	*flow.Record
	TimeFlowStart   int64
	TimeFlowEnd     int64
	TimeFlowStartMs int64
	TimeFlowEndMs   int64
}
