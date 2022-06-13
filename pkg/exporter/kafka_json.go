package exporter

import (
	"context"
	"encoding/json"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	kafkago "github.com/segmentio/kafka-go"
	"github.com/sirupsen/logrus"
)

var klog = logrus.WithField("component", "exporter/KafkaJSON")

type kafkaWriter interface {
	WriteMessages(ctx context.Context, msgs ...kafkago.Message) error
}

type KafkaJSON struct {
	Writer kafkaWriter
}

func (kj *KafkaJSON) ExportFlows(ctx context.Context, input <-chan []*flow.Record) {
	klog.Info("starting Kafka exporter")
	for records := range input {
		msgs := make([]kafkago.Message, 0, len(records))
		for _, record := range records {
			msgBytes, err := json.Marshal(JSONRecord{
				Record:          record,
				TimeFlowStart:   record.TimeFlowStart.Unix(),
				TimeFlowEnd:     record.TimeFlowEnd.Unix(),
				TimeFlowStartMs: record.TimeFlowStart.UnixMilli(),
				TimeFlowEndMs:   record.TimeFlowEnd.UnixMilli(),
			})
			if err != nil {
				klog.WithError(err).Warn("can't convert flow record to JSON. Ignoring")
				continue
			}
			msgs = append(msgs, kafkago.Message{
				Value: msgBytes,
			})
		}
		if err := kj.Writer.WriteMessages(ctx, msgs...); err != nil {
			klog.WithError(err).Error("can't write messages into Kafka")
		}
	}
}

type JSONRecord struct {
	*flow.Record
	TimeFlowStart   int64
	TimeFlowEnd     int64
	TimeFlowStartMs int64
	TimeFlowEndMs   int64
}

//func (jr *JSONRecord) AsFlatJSON() ([]byte, error) {
//
//}