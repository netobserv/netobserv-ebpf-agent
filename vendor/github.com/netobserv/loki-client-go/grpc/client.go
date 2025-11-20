package grpc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/gogo/protobuf/proto"
	"github.com/netobserv/loki-client-go/pkg/backoff"
	"github.com/netobserv/loki-client-go/pkg/logproto"
	"github.com/netobserv/loki-client-go/pkg/metrics"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/version"
	"github.com/prometheus/prometheus/promql/parser"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	// Label reserved to override the tenant ID while processing pipeline stages
	ReservedLabelTenantID = "__tenant_id__"

	transportGRPC = "grpc"
)

var (
	UserAgent = fmt.Sprintf("loki-grpc-client/%s", version.Version)
)

func init() {
	metrics.RegisterMetrics()
}

// Client for pushing logs via GRPC
type Client struct {
	logger  log.Logger
	cfg     Config
	conn    *grpc.ClientConn
	pusher  logproto.PusherClient
	quit    chan struct{}
	once    sync.Once
	entries chan entry
	wg      sync.WaitGroup

	externalLabels model.LabelSet
}

// New creates a new GRPC client from config
func New(cfg Config) (*Client, error) {
	logger := level.NewFilter(log.NewLogfmtLogger(os.Stdout), level.AllowWarn())
	return NewWithLogger(cfg, logger)
}

// NewWithDefault creates a new client with default configuration
func NewWithDefault(serverAddress string) (*Client, error) {
	cfg, err := NewDefaultConfig(serverAddress)
	if err != nil {
		return nil, err
	}
	return New(cfg)
}

// NewWithLogger creates a new GRPC client with a logger and config
func NewWithLogger(cfg Config, logger log.Logger) (*Client, error) {
	if cfg.ServerAddress == "" {
		return nil, errors.New("grpc client needs server address")
	}

	c := &Client{
		logger:         log.With(logger, "component", "grpc-client", "host", cfg.ServerAddress),
		cfg:            cfg,
		quit:           make(chan struct{}),
		entries:        make(chan entry),
		externalLabels: cfg.ExternalLabels.LabelSet,
	}

	// Initialize connection
	if err := c.connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to GRPC server: %w", err)
	}

	// Initialize counters to 0
	for _, counter := range metrics.CountersWithHost {
		counter.WithLabelValues(c.cfg.ServerAddress, transportGRPC).Add(0)
	}

	c.wg.Add(1)
	go c.run()
	return c, nil
}

// connect establishes GRPC connection
func (c *Client) connect() error {
	opts, err := c.cfg.BuildDialOptions()
	if err != nil {
		return err
	}

	conn, err := grpc.NewClient(c.cfg.ServerAddress, opts...)
	if err != nil {
		return err
	}

	c.conn = conn
	c.pusher = logproto.NewPusherClient(conn)

	level.Info(c.logger).Log("msg", "connected to GRPC server", "address", c.cfg.ServerAddress)
	return nil
}

func (c *Client) run() {
	batches := map[string]*batch{}

	// Batch timer logic similar to HTTP client
	minWaitCheckFrequency := 10 * time.Millisecond
	maxWaitCheckFrequency := c.cfg.BatchWait / 10
	if maxWaitCheckFrequency < minWaitCheckFrequency {
		maxWaitCheckFrequency = minWaitCheckFrequency
	}

	maxWaitCheck := time.NewTicker(maxWaitCheckFrequency)

	defer func() {
		// Send all pending batches
		for tenantID, batch := range batches {
			c.sendBatch(tenantID, batch)
		}
		c.wg.Done()
	}()

	for {
		select {
		case <-c.quit:
			return

		case e := <-c.entries:
			batch, ok := batches[e.tenantID]

			// Create new batch if doesn't exist
			if !ok {
				batches[e.tenantID] = newBatch(e.tenantID, e)
				break
			}

			// Send batch if adding entry would exceed max size
			if batch.sizeBytesAfter(e) > c.cfg.BatchSize {
				c.sendBatch(e.tenantID, batch)
				batches[e.tenantID] = newBatch(e.tenantID, e)
				break
			}

			// Add entry to existing batch
			batch.add(e)

		case <-maxWaitCheck.C:
			// Send batches that have reached max wait time
			for tenantID, batch := range batches {
				if batch.age() < c.cfg.BatchWait {
					continue
				}

				c.sendBatch(tenantID, batch)
				delete(batches, tenantID)
			}
		}
	}
}

func (c *Client) sendBatch(tenantID string, batch *batch) {
	req, entriesCount := batch.createPushRequest()

	if len(req.Streams) == 0 {
		return
	}

	// Calculate wire bytes (protobuf size) to match HTTP client behavior
	wireBytes := float64(proto.Size(req))
	metrics.EncodedBytes.WithLabelValues(c.cfg.ServerAddress, transportGRPC).Add(wireBytes)

	backoffCtx := context.Background()
	backoffInstance := backoff.New(backoffCtx, c.cfg.BackoffConfig)
	var status string
	var err error

	for backoffInstance.Ongoing() {
		start := time.Now()
		// Create a fresh context for each retry attempt
		pushCtx := context.Background()
		err = c.push(pushCtx, tenantID, req)

		// Convert error to status code for metrics
		status = c.getStatusCode(err)
		metrics.RequestDuration.WithLabelValues(status, c.cfg.ServerAddress, transportGRPC).Observe(time.Since(start).Seconds())

		if err == nil {
			// Success metrics
			metrics.SentEntries.WithLabelValues(c.cfg.ServerAddress, transportGRPC).Add(float64(entriesCount))
			metrics.SentBytes.WithLabelValues(c.cfg.ServerAddress, transportGRPC).Add(wireBytes)

			c.updateStreamLagMetrics(req.Streams)
			return
		}

		level.Warn(c.logger).Log("msg", "error sending batch via GRPC, will retry", "status", status, "error", err)
		metrics.BatchRetries.WithLabelValues(c.cfg.ServerAddress, transportGRPC).Inc()
		backoffInstance.Wait()
	}

	// Failed after all retries
	if err != nil {
		level.Error(c.logger).Log("msg", "final error sending batch via GRPC", "status", status, "error", err)
		metrics.DroppedEntries.WithLabelValues(c.cfg.ServerAddress, transportGRPC).Add(float64(entriesCount))
		metrics.DroppedBytes.WithLabelValues(c.cfg.ServerAddress, transportGRPC).Add(wireBytes)
	}
}

func (c *Client) push(ctx context.Context, tenantID string, req *logproto.PushRequest) error {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	// Add tenant ID to metadata if specified
	if tenantID != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "x-scope-orgid", tenantID)
	}

	// Add user agent
	ctx = metadata.AppendToOutgoingContext(ctx, "user-agent", UserAgent)

	// gRPC handles connection management automatically
	_, err := c.pusher.Push(ctx, req)
	return err
}

func (c *Client) getStatusCode(err error) string {
	if err == nil {
		return "200"
	}

	st, ok := status.FromError(err)
	if !ok {
		return "Unknown"
	}

	// Convert gRPC status codes to HTTP-like status codes for metrics compatibility
	switch st.Code() {
	case codes.OK:
		return "200"
	case codes.ResourceExhausted:
		return "429" // Rate limited
	case codes.Internal, codes.Aborted, codes.Unavailable:
		return "500"
	case codes.DeadlineExceeded:
		return "504" // Gateway timeout
	default:
		return strconv.Itoa(int(st.Code()))
	}
}

func (c *Client) getTenantID(labels model.LabelSet) string {
	// Check if overridden in pipeline stages
	if value, ok := labels[ReservedLabelTenantID]; ok {
		return string(value)
	}

	// Check config
	if c.cfg.TenantID != "" {
		return c.cfg.TenantID
	}

	return ""
}

// Stop the client
func (c *Client) Stop() {
	c.once.Do(func() {
		close(c.quit)

		if c.conn != nil {
			c.conn.Close()
		}
	})
	c.wg.Wait()
}

// updateStreamLagMetrics updates lag metrics to match HTTP client behavior
func (c *Client) updateStreamLagMetrics(streams []logproto.Stream) {
	for _, s := range streams {
		lbls, err := parser.ParseMetric(s.Labels)
		if err != nil {
			// is this possible?
			level.Warn(c.logger).Log("msg", "error converting stream label string to label.Labels, cannot update lagging metric", "error", err)
			return
		}
		var lblSet model.LabelSet
		for i := range lbls {
			if lbls[i].Name == metrics.LatencyLabel {
				lblSet = model.LabelSet{
					model.LabelName(metrics.HostLabel):    model.LabelValue(c.cfg.ServerAddress),
					model.LabelName(metrics.LatencyLabel): model.LabelValue(lbls[i].Value),
				}
			}
		}
		if lblSet != nil {
			metrics.StreamLag.With(lblSet).Set(time.Since(s.Entries[len(s.Entries)-1].Timestamp).Seconds())
		}
	}
}

// Handle implements EntryHandler; adds a new line to the next batch; send is async
func (c *Client) Handle(ls model.LabelSet, t time.Time, s string) error {
	if len(c.externalLabels) > 0 {
		ls = c.externalLabels.Merge(ls)
	}

	// Get tenant ID and remove special label
	tenantID := c.getTenantID(ls)
	if _, ok := ls[ReservedLabelTenantID]; ok {
		ls = ls.Clone()
		delete(ls, ReservedLabelTenantID)
	}

	c.entries <- entry{tenantID, ls, logproto.Entry{
		Timestamp: t,
		Line:      s,
	}}
	return nil
}

func (c *Client) UnregisterLatencyMetric(labels model.LabelSet) {
	labels[metrics.HostLabel] = model.LabelValue(c.cfg.ServerAddress)
	metrics.StreamLag.Delete(labels)
}
