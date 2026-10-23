package rawdb

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/rlp"
)

type dataHashLookupErrorDB struct {
	ethdb.KeyValueReader
	hasErr, getErr error
}

func (d dataHashLookupErrorDB) Has(key []byte) (bool, error) {
	if d.hasErr != nil {
		return false, d.hasErr
	}
	return d.KeyValueReader.Has(key)
}
func (d dataHashLookupErrorDB) Get(key []byte) ([]byte, error) {
	if d.getErr != nil {
		return nil, d.getErr
	}
	return d.KeyValueReader.Get(key)
}

func TestDataHashLookupJournalErrorsAndBounds(t *testing.T) {
	db := memorydb.New()
	defer db.Close()
	if hashes, err := ReadDataHashLookupJournal(db, 1); err != nil || len(hashes) != 0 {
		t.Fatalf("missing journal: %v %v", hashes, err)
	}
	hash := common.HexToHash("0x01")
	encoded, err := rlp.EncodeToBytes([]*common.Hash{&hash})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Put(dataHashesKey(1), encoded); err != nil {
		t.Fatal(err)
	}
	hashes, err := ReadDataHashLookupJournal(db, 1)
	if err != nil || len(hashes) != 1 || *hashes[0] != hash {
		t.Fatalf("valid journal: %v %v", hashes, err)
	}
	failure := errors.New("read failure")
	for _, reader := range []dataHashLookupErrorDB{{KeyValueReader: db, hasErr: failure}, {KeyValueReader: db, getErr: failure}} {
		if _, err := ReadDataHashLookupJournal(reader, 1); !errors.Is(err, failure) {
			t.Fatalf("swallowed database failure: %v", err)
		}
	}
	for _, malformed := range [][]byte{{0xff}, make([]byte, 32*33+17)} {
		if err := db.Put(dataHashesKey(1), malformed); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadDataHashLookupJournal(db, 1); err == nil {
			t.Fatal("malformed journal accepted")
		}
	}
}
