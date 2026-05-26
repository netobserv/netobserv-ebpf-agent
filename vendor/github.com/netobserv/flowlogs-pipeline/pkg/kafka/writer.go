package kafka

import (
	"fmt"
	"time"

	"github.com/netobserv/flowlogs-pipeline/pkg/api"
	"github.com/netobserv/flowlogs-pipeline/pkg/pipeline/utils"
	kafkago "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/compress"
	log "github.com/sirupsen/logrus"
)

const (
	defaultReadTimeoutSeconds  = int64(10)
	defaultWriteTimeoutSeconds = int64(10)
)

func NewWriter(config *api.EncodeKafka) (*kafkago.Writer, error) {
	var balancer kafkago.Balancer
	switch config.Balancer {
	case api.KafkaRoundRobin:
		balancer = &kafkago.RoundRobin{}
	case api.KafkaLeastBytes:
		balancer = &kafkago.LeastBytes{}
	case api.KafkaHash:
		balancer = &kafkago.Hash{}
	case api.KafkaCrc32:
		balancer = &kafkago.CRC32Balancer{}
	case api.KafkaMurmur2:
		balancer = &kafkago.Murmur2Balancer{}
	default:
		balancer = nil
	}

	readTimeoutSecs := defaultReadTimeoutSeconds
	if config.ReadTimeout != 0 {
		readTimeoutSecs = config.ReadTimeout
	}

	writeTimeoutSecs := defaultWriteTimeoutSeconds
	if config.WriteTimeout != 0 {
		writeTimeoutSecs = config.WriteTimeout
	}

	transport := kafkago.Transport{}
	if config.TLS != nil {
		log.Infof("Using TLS configuration: %v", config.TLS)
		tlsConfig, err := config.TLS.Build()
		if err != nil {
			return nil, err
		}
		transport.TLS = tlsConfig
	}

	if config.SASL != nil {
		m, err := utils.SetupSASLMechanism(config.SASL)
		if err != nil {
			return nil, err
		}
		transport.SASL = m
	}

	var compression compress.Compression
	if config.Compression != "" {
		if err := compression.UnmarshalText([]byte(config.Compression)); err != nil {
			return nil, fmt.Errorf("wrong Kafka compression value %q (admitted: none, gzip, snappy, lz4, zstd): %w",
				config.Compression, err)
		}
	}

	kafkaWriter := kafkago.Writer{
		Addr:         kafkago.TCP(config.Address),
		Topic:        config.Topic,
		Balancer:     balancer,
		ReadTimeout:  time.Duration(readTimeoutSecs) * time.Second,
		WriteTimeout: time.Duration(writeTimeoutSecs) * time.Second,
		BatchSize:    config.BatchSize,
		BatchBytes:   config.BatchBytes,
		Compression:  compression,
		// Temporary fix may be we should implement a batching systems
		// https://github.com/segmentio/kafka-go/issues/326#issuecomment-519375403
		BatchTimeout: time.Nanosecond,
		Transport:    &transport,
	}

	return &kafkaWriter, nil
}
