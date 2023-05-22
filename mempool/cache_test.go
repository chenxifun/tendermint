package mempool

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCacheRemove(t *testing.T) {
	cache := newMapTxCache(100)
	numTxs := 10000
	txs := make([][]byte, numTxs)
	for i := 0; i < numTxs; i++ {
		txBytes := make([]byte, 32)
		_, err := rand.Read(txBytes)
		require.NoError(t, err)
		txs[i] = txBytes
	}
	txChan := make(chan int, 1000)
	startCh := make(chan struct{})
	go func() {
		for i := 0; i < numTxs; i++ {
			go func(i int) {
				<-startCh
				// probability of collision is 2**-256
				cache.Push(txs[i])
				txChan <- i
				// make sure its added to both the linked list and the map
			}(i)
		}
		close(startCh)
	}()

	go func() {
		for i := range txChan {
			cache.Remove(txs[i])
		}
	}()
	time.Sleep(10 * time.Second)

}
