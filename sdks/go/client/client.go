// Package client provides a gRPC client for the Settled audit log server.
// Proto stubs must be generated before use; from sdks/go run:
//
//	./scripts/generate.sh
//
// (which invokes protoc against the canonical proto/settled.v1.proto at the
// repo root).
package client

import (
	"context"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/richardadalton/settled/sdks/go/client/proto"
)

// Option configures a SettledClient.
type Option func(*clientConfig)

type clientConfig struct {
	apiKey string
}

// WithAPIKey sets the API key sent as `authorization: Bearer <key>` on every request.
func WithAPIKey(key string) Option {
	return func(c *clientConfig) { c.apiKey = key }
}

type apiKeyCredentials struct{ key string }

func (a apiKeyCredentials) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + a.key}, nil
}

func (a apiKeyCredentials) RequireTransportSecurity() bool { return false }

// SignedTreeHead mirrors the protobuf message with native Go types.
type SignedTreeHead struct {
	TreeSize    uint64
	RootHash    []byte
	TimestampNs int64
	Signature   []byte
	PublicKey   []byte
	KeyVersion  uint32
}

// AppendResult is returned from Append.
type AppendResult struct {
	Seq         uint64
	TimestampNs int64
	LeafHash    []byte
	Key         []byte
}

// Entry is a single log entry.
type Entry struct {
	Seq         uint64
	TimestampNs int64
	Key         []byte
	Data        []byte
	LeafHash    []byte
}

// InclusionProofResult is returned from InclusionProof.
type InclusionProofResult struct {
	LeafIndex uint64
	TreeSize  uint64
	Proof     [][]byte
	Sth       SignedTreeHead
}

// ConsistencyProofResult is returned from ConsistencyProof.
type ConsistencyProofResult struct {
	OldSize uint64
	NewSize uint64
	Proof   [][]byte
	OldSth  SignedTreeHead
	NewSth  SignedTreeHead
}

func fromPbSth(s *pb.SignedTreeHead) SignedTreeHead {
	return SignedTreeHead{
		TreeSize:    s.TreeSize,
		RootHash:    s.RootHash,
		TimestampNs: s.TimestampNs,
		Signature:   s.Signature,
		PublicKey:   s.PublicKey,
		KeyVersion:  s.KeyVersion,
	}
}

// SettledClient is a synchronous gRPC client for SettledLog.
type SettledClient struct {
	conn *grpc.ClientConn
	stub pb.SettledLogClient
}

// New connects to the server at addr, with optional configuration.
func New(addr string, opts ...Option) (*SettledClient, error) {
	cfg := &clientConfig{}
	for _, o := range opts {
		o(cfg)
	}
	grpcOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if cfg.apiKey != "" {
		grpcOpts = append(grpcOpts, grpc.WithPerRPCCredentials(apiKeyCredentials{cfg.apiKey}))
	}
	conn, err := grpc.NewClient(addr, grpcOpts...)
	if err != nil {
		return nil, err
	}
	return &SettledClient{conn: conn, stub: pb.NewSettledLogClient(conn)}, nil
}

// Close closes the underlying connection.
func (c *SettledClient) Close() error { return c.conn.Close() }

// Append appends an entry and returns its sequence number and leaf hash.
func (c *SettledClient) Append(ctx context.Context, key, data []byte) (*AppendResult, error) {
	res, err := c.stub.Append(ctx, &pb.AppendRequest{Key: key, Data: data})
	if err != nil {
		return nil, err
	}
	return &AppendResult{Seq: res.Seq, TimestampNs: res.TimestampNs, LeafHash: res.LeafHash, Key: res.Key}, nil
}

// Get retrieves a log entry by sequence number.
func (c *SettledClient) Get(ctx context.Context, seq uint64) (*Entry, error) {
        res, err := c.stub.Get(ctx, &pb.GetRequest{Seq: seq})
        if err != nil {
                return nil, err
        }
        e := res.Entry
        return &Entry{Seq: e.Seq, TimestampNs: e.TimestampNs, Key: e.Key, Data: e.Data, LeafHash: e.LeafHash}, nil
}

// GetLatestResult is returned from GetLatest.
type GetLatestResult struct {
	Entries        []Entry
	TotalAvailable uint64
}

// GetLatest returns the most-recent n entries (newest first). n=0 is treated
// as 1 by the server. Values above the server cap (1000) are silently clamped;
// check TotalAvailable to detect truncation and use ListEntries to page further.
func (c *SettledClient) GetLatest(ctx context.Context, n uint32) (*GetLatestResult, error) {
	res, err := c.stub.GetLatest(ctx, &pb.GetLatestRequest{N: n})
	if err != nil {
		return nil, err
	}
	out := make([]Entry, len(res.Entries))
	for i, e := range res.Entries {
		out[i] = Entry{
			Seq:         e.Seq,
			TimestampNs: e.TimestampNs,
			Key:         e.Key,
			Data:        e.Data,
			LeafHash:    e.LeafHash,
		}
	}
	return &GetLatestResult{Entries: out, TotalAvailable: res.TotalAvailable}, nil
}

// GetSth retrieves a Signed Tree Head. Pass treeSize=0 for latest.
func (c *SettledClient) GetSth(ctx context.Context, treeSize uint64) (*SignedTreeHead, error) {
	res, err := c.stub.GetSth(ctx, &pb.GetSthRequest{TreeSize: treeSize})
	if err != nil {
		return nil, err
	}
	sth := fromPbSth(res.Sth)
	return &sth, nil
}

// InclusionProof returns an inclusion proof. Pass treeSize=0 for latest STH.
func (c *SettledClient) InclusionProof(ctx context.Context, seq, treeSize uint64) (*InclusionProofResult, error) {
	res, err := c.stub.InclusionProof(ctx, &pb.InclusionProofRequest{Seq: seq, TreeSize: treeSize})
	if err != nil {
		return nil, err
	}
	return &InclusionProofResult{
		LeafIndex: res.LeafIndex,
		TreeSize:  res.TreeSize,
		Proof:     res.Proof,
		Sth:       fromPbSth(res.Sth),
	}, nil
}

// ConsistencyProof returns a consistency proof. Pass newSize=0 for latest STH.
func (c *SettledClient) ConsistencyProof(ctx context.Context, oldSize, newSize uint64) (*ConsistencyProofResult, error) {
	res, err := c.stub.ConsistencyProof(ctx, &pb.ConsistencyProofRequest{OldSize: oldSize, NewSize: newSize})
	if err != nil {
		return nil, err
	}
	return &ConsistencyProofResult{
		OldSize: res.OldSize,
		NewSize: res.NewSize,
		Proof:   res.Proof,
		OldSth:  fromPbSth(res.OldSth),
		NewSth:  fromPbSth(res.NewSth),
	}, nil
}

// WatchEntries opens a server-streaming Watch RPC and returns a channel that
// receives entries as they arrive.  fromSeq > 0 replays history first;
// fromSeq == 0 streams only entries appended after the call.
// The goroutine exits (closing ch and errc) when the context is cancelled,
// the server closes the stream, or an error occurs.
func (c *SettledClient) WatchEntries(ctx context.Context, fromSeq uint64) (<-chan Entry, <-chan error) {
	ch := make(chan Entry, 64)
	errc := make(chan error, 1)
	go func() {
		defer close(ch)
		defer close(errc)
		stream, err := c.stub.Watch(ctx, &pb.WatchRequest{FromSeq: fromSeq})
		if err != nil {
			errc <- err
			return
		}
		for {
			e, err := stream.Recv()
			if err != nil {
				if err != io.EOF {
					errc <- err
				}
				return
			}
			select {
			case ch <- Entry{
				Seq:         e.Seq,
				TimestampNs: e.TimestampNs,
				Key:         e.Key,
				Data:        e.Data,
				LeafHash:    e.LeafHash,
			}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, errc
}

// ListEntriesResult is returned from ListEntries.
type ListEntriesResult struct {
	Entries    []Entry
	NextCursor uint64
}

// ListEntries returns a seq-ordered page of entries within [fromSeq, toSeq).
// toSeq=0 scans to the end of the log. cursor=0 starts from fromSeq; pass
// NextCursor from the previous response to continue. limit=0 uses the server
// default (50).
func (c *SettledClient) ListEntries(ctx context.Context, fromSeq, toSeq, cursor uint64, limit uint32) (*ListEntriesResult, error) {
	res, err := c.stub.ListEntries(ctx, &pb.ListEntriesRequest{
		FromSeq: fromSeq,
		ToSeq:   toSeq,
		Cursor:  cursor,
		Limit:   limit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Entry, len(res.Entries))
	for i, e := range res.Entries {
		out[i] = Entry{
			Seq:         e.Seq,
			TimestampNs: e.TimestampNs,
			Key:         e.Key,
			Data:        e.Data,
			LeafHash:    e.LeafHash,
		}
	}
	return &ListEntriesResult{Entries: out, NextCursor: res.NextCursor}, nil
}

// GetByKeyResult is returned from GetByKey.
type GetByKeyResult struct {
	Entries    []Entry
	NextCursor uint64
}

// GetByKey retrieves all entries for a given key with cursor-based pagination.
// Pass cursor=0 to start from the beginning; limit=0 uses the server default (50).
// NextCursor=0 in the result means no further pages exist.
func (c *SettledClient) GetByKey(ctx context.Context, key []byte, cursor uint64, limit uint32) (*GetByKeyResult, error) {
	res, err := c.stub.GetByKey(ctx, &pb.GetByKeyRequest{Key: key, Cursor: cursor, Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]Entry, len(res.Entries))
	for i, e := range res.Entries {
		out[i] = Entry{
			Seq:         e.Seq,
			TimestampNs: e.TimestampNs,
			Key:         e.Key,
			Data:        e.Data,
			LeafHash:    e.LeafHash,
		}
	}
	return &GetByKeyResult{Entries: out, NextCursor: res.NextCursor}, nil
}

// AppendEntry is a single entry to write in AppendStream.
type AppendEntry struct {
	Key  []byte
	Data []byte
}

// AppendStream appends entries in batches of batchSize, writing results to out.
// out is closed when all entries are processed or an error occurs.
func (c *SettledClient) AppendStream(ctx context.Context, entries <-chan AppendEntry, batchSize int) (<-chan *AppendResult, <-chan error) {
	if batchSize <= 0 {
		batchSize = 100
	}
	out := make(chan *AppendResult, batchSize)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		batch := make([]AppendEntry, 0, batchSize)
		flush := func() error {
			for _, e := range batch {
				r, err := c.Append(ctx, e.Key, e.Data)
				if err != nil {
					return err
				}
				out <- r
			}
			batch = batch[:0]
			return nil
		}
		for e := range entries {
			batch = append(batch, e)
			if len(batch) >= batchSize {
				if err := flush(); err != nil {
					errc <- err
					io.Discard.Write(nil)
					return
				}
			}
		}
		if err := flush(); err != nil {
			errc <- err
		}
	}()
	return out, errc
}
