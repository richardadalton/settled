// Package client provides a gRPC client for the Settled audit log server.
// Proto stubs must be generated before use:
//
//	protoc --go_out=. --go-grpc_out=. \
//	  -I../../crates/settled-server/proto \
//	  settled.v1.proto
package client

import (
	"context"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/richardadalton/settled/sdks/go/client/proto"
)

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

// New connects to the server at addr.
func New(addr string) (*SettledClient, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
	return &AppendResult{Seq: res.Seq, TimestampNs: res.TimestampNs, LeafHash: res.LeafHash}, nil
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
