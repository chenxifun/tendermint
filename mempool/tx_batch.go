package mempool

import (
	"github.com/tendermint/tendermint/types"
	"sync"
	"sync/atomic"
)

const maxTxBatchSize int = 5000

type mempoolTxBatch struct {
	mtx        sync.Mutex
	hash       [32]byte // txheader hash
	txHeader   []byte   // 所有交易的第一个字节
	txs        types.Txs
	size       int
	height     int64 // height that this tx had been validated in
	gasWanted  int64 // amount of gas this tx states it will require
	txByteSize int

	// ids of peers who've sent us this tx (as a map for quick lookups).
	// senders: PeerID -> bool
	senders sync.Map
}

func (memTx *mempoolTxBatch) Height() int64 {
	return atomic.LoadInt64(&memTx.height)
}

func (memTx *mempoolTxBatch) AddTx(tx *mempoolTx) {
	memTx.mtx.Lock()
	defer memTx.mtx.Unlock()
	memTx.txs = append(memTx.txs, tx.tx)
	memTx.txHeader = append(memTx.txHeader, tx.tx[0])
	memTx.size++
	memTx.gasWanted += tx.gasWanted
	memTx.txByteSize += len(tx.tx)
	return
}

func (memTx *mempoolTxBatch) AddTxIndex(tx *mempoolTx, i int) {
	memTx.mtx.Lock()
	defer memTx.mtx.Unlock()
	memTx.txs[i] = tx.tx
	memTx.txHeader[i] = tx.tx[0]
	memTx.gasWanted += tx.gasWanted
	memTx.txByteSize += len(tx.tx)
	return
}

func (memTx *mempoolTxBatch) isFull() bool {
	return memTx.size >= maxTxBatchSize
}

// 校验个毛线，都是自己人
//func (tb *mempoolTxBatch) Validate() bool {
//	if len(tb.txHeader) != len(tb.txs) {
//		return false
//	}
//	if !bytes.Equal(tmhash.Sum(tb.txHeader), tb.hash) {
//		return false
//	}
//	return true
//}
