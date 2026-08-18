package common

import (
	"fmt"
	"os"
	"strings"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
)

func BuildSASLConfig(cfg *config.Agent) (sasl.Mechanism, error) {
	// Read client ID
	id, err := os.ReadFile(cfg.Flows.KafkaSASLClientIDPath)
	if err != nil {
		return nil, err
	}
	strID := strings.TrimSpace(string(id))
	// Read password
	pwd, err := os.ReadFile(cfg.Flows.KafkaSASLClientSecretPath)
	if err != nil {
		return nil, err
	}
	strPwd := strings.TrimSpace(string(pwd))
	var mechanism sasl.Mechanism
	switch cfg.Flows.KafkaSASLType {
	case "plain":
		mechanism = plain.Mechanism{Username: strID, Password: strPwd}
	case "scramSHA512":
		mechanism, err = scram.Mechanism(scram.SHA512, strID, strPwd)
	default:
		err = fmt.Errorf("unknown SASL type: %s", cfg.Flows.KafkaSASLType)
	}
	if err != nil {
		return nil, err
	}
	return mechanism, nil
}
