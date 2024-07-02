package observability_lib

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/model"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/types"
	"k8s.io/klog/v2/textlogger"
)

func NewNBClientWithConfig(ctx context.Context, cfg nbConfig) (client.Client, error) {
	dbModel, err := nbdb.FullDatabaseModel()
	if err != nil {
		return nil, err
	}

	// define client indexes for objects that are using dbIDs
	dbModel.SetIndexes(map[string][]model.ClientIndex{
		nbdb.ACLTable:           {{Columns: []model.ColumnKey{{Column: "external_ids", Key: types.PrimaryIDKey}}}},
		nbdb.DHCPOptionsTable:   {{Columns: []model.ColumnKey{{Column: "external_ids", Key: types.PrimaryIDKey}}}},
		nbdb.LoadBalancerTable:  {{Columns: []model.ColumnKey{{Column: "name"}}}},
		nbdb.LogicalSwitchTable: {{Columns: []model.ColumnKey{{Column: "name"}}}},
		nbdb.LogicalRouterTable: {{Columns: []model.ColumnKey{{Column: "name"}}}},
	})

	c, err := newClient(cfg, dbModel)
	if err != nil {
		return nil, err
	}

	//_, err = c.MonitorAll(ctx)

	_, err = c.Monitor(ctx,
		c.NewMonitor(
			client.WithTable(&nbdb.ACL{}),
			client.WithTable(&nbdb.LogicalSwitchPort{}),
			client.WithTable(&nbdb.LogicalSwitch{}),
			client.WithTable(&nbdb.LoadBalancer{}),
			client.WithTable(&nbdb.QoS{}),
			client.WithTable(&nbdb.LogicalRouter{}),
			client.WithTable(&nbdb.LogicalRouterPort{}),
			client.WithTable(&nbdb.LogicalRouterStaticRoute{}),
			client.WithTable(&nbdb.LogicalRouterPolicy{}),
			client.WithTable(&nbdb.NAT{}),
		),
	)

	if err != nil {
		c.Close()
		return nil, err
	}

	return c, nil
}

// newClient creates a new client object given the provided config
// the stopCh is required to ensure the goroutine for ssl cert
// update is not leaked
func newClient(cfg nbConfig, dbModel model.ClientDBModel, opts ...client.Option) (client.Client, error) {
	const connectTimeout time.Duration = types.OVSDBTimeout * 2
	const inactivityTimeout time.Duration = types.OVSDBTimeout * 18
	// Don't log anything from the libovsdb client by default
	config := textlogger.NewConfig(textlogger.Verbosity(0))
	logger := textlogger.NewLogger(config)

	options := []client.Option{
		// Reading and parsing the DB after reconnect at scale can (unsurprisingly)
		// take longer than a normal ovsdb operation. Give it a bit more time so
		// we don't time out and enter a reconnect loop. In addition it also enables
		// inactivity check on the ovsdb connection.
		client.WithInactivityCheck(inactivityTimeout, connectTimeout, &backoff.ZeroBackOff{}),
		client.WithLeaderOnly(true),
		client.WithLogger(&logger),
	}
	options = append(options, opts...)

	for _, endpoint := range strings.Split(cfg.address, ",") {
		options = append(options, client.WithEndpoint(endpoint))
	}
	if cfg.scheme != "unix" {
		return nil, fmt.Errorf("only unix scheme is supported for now")
	}

	client, err := client.NewOVSDBClient(dbModel, options...)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	err = client.Connect(ctx)
	if err != nil {
		return nil, err
	}

	return client, nil
}
