package write

import (
	"context"
	cryptotls "crypto/tls"
	"encoding/json"
	"fmt"

	"github.com/netobserv/flowlogs-pipeline/pkg/api"
	"github.com/netobserv/flowlogs-pipeline/pkg/config"
	"github.com/netobserv/flowlogs-pipeline/pkg/pipeline/write/grpc"
	"github.com/netobserv/flowlogs-pipeline/pkg/pipeline/write/grpc/genericmap"
	"github.com/netobserv/flowlogs-pipeline/pkg/tlsprofile"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/anypb"
)

type writeGRPC struct {
	hostIP     string
	hostPort   int
	clientConn *grpc.ClientConnection
}

// Write writes a flow before being stored
func (t *writeGRPC) Write(v config.GenericMap) {
	logrus.Tracef("entering writeGRPC Write %s", v)
	value, _ := json.Marshal(v)
	if _, err := t.clientConn.Client().Send(context.TODO(), &genericmap.Flow{
		GenericMap: &anypb.Any{
			Value: value,
		},
	}); err != nil {
		logrus.Errorf("writeGRPC send error: %v", err)
	}
}

// NewWriteGRPC create a new write
func NewWriteGRPC(params config.StageParam) (Writer, error) {
	logrus.Debugf("entering NewWriteGRPC")

	writeGRPC := &writeGRPC{}
	if params.Write != nil && params.Write.GRPC != nil {
		if err := params.Write.GRPC.Validate(); err != nil {
			return nil, fmt.Errorf("the provided config is not valid: %w", err)
		}
		writeGRPC.hostIP = params.Write.GRPC.TargetHost
		writeGRPC.hostPort = params.Write.GRPC.TargetPort
	} else {
		return nil, fmt.Errorf("write.grpc param is mandatory: %v", params.Write)
	}
	logrus.Debugf("NewWriteGRPC ConnectClient %s:%d...", writeGRPC.hostIP, writeGRPC.hostPort)
	tlsCfg, err := resolveTLSConfig(params.Write.GRPC.TLS)
	if err != nil {
		return nil, err
	}
	clientConn, err := grpc.ConnectClient(writeGRPC.hostIP, writeGRPC.hostPort, tlsCfg)
	if err != nil {
		return nil, err
	}
	writeGRPC.clientConn = clientConn
	return writeGRPC, nil
}

// resolveTLSConfig builds the gRPC client TLS configuration for the writer.
// If cfg is set, it is used to build the explicit TLS configuration, which is
// then extended with any TLS-profile environment overrides (TLS_MIN_VERSION,
// TLS_CIPHER_SUITES, TLS_CURVE_PREFERENCES).
// If cfg is nil, a TLS configuration is only created when the environment
// yields at least one valid override; otherwise nil is returned and the
// connection remains insecure, preserving prior behavior.
func resolveTLSConfig(cfg *api.ClientTLS) (*cryptotls.Config, error) {
	if cfg != nil {
		tlsCfg, err := cfg.Build()
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
		if _, err := tlsprofile.Apply(tlsCfg); err != nil {
			return nil, fmt.Errorf("invalid TLS profile override: %w", err)
		}
		return tlsCfg, nil
	}

	envCfg := &cryptotls.Config{MinVersion: cryptotls.VersionTLS13}
	applied, err := tlsprofile.Apply(envCfg)
	if err != nil {
		return nil, fmt.Errorf("invalid TLS profile override: %w", err)
	}
	if !applied {
		return nil, nil
	}
	return envCfg, nil
}
