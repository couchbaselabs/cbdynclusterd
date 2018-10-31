package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dgraph-io/badger"
	"github.com/golang/glog"
)

type ClusterMetaJSON struct {
	Owner   string `json:"owner,omitempty"`
	Timeout string `json:"timeout,omitempty"`
}

type ClusterMeta struct {
	Owner   string
	Timeout time.Time
}

type MetaDataStore struct {
	db *badger.DB
}

var DEFAULT_CLUSTER_META ClusterMeta = ClusterMeta{
	Owner:   "unknown",
	Timeout: DEFAULT_CLUSTER_TIMEOUT,
}

func (store *MetaDataStore) serializeMeta(meta ClusterMeta) ([]byte, error) {
	metaJSON := ClusterMetaJSON{
		Owner:   meta.Owner,
		Timeout: meta.Timeout.Format(time.RFC3339),
	}

	metaBytes, err := json.Marshal(metaJSON)
	if err != nil {
		return nil, err
	}

	return metaBytes, nil
}

func (store *MetaDataStore) deserializeMeta(bytes []byte) (ClusterMeta, error) {
	var metaJSON ClusterMetaJSON
	err := json.Unmarshal(bytes, &metaJSON)
	if err != nil {
		return ClusterMeta{}, err
	}

	parsedTimeout, err := time.Parse(time.RFC3339Nano, metaJSON.Timeout)
	if err != nil {
		parsedTimeout = DEFAULT_CLUSTER_TIMEOUT
	}

	return ClusterMeta{
		Owner:   metaJSON.Owner,
		Timeout: parsedTimeout,
	}, nil
}

func (store *MetaDataStore) Open(dir string) error {
	opts := badger.DefaultOptions
	opts.Dir = dir
	opts.ValueDir = dir

	db, err := badger.Open(opts)
	if err != nil {
		return err
	}

	store.db = db
	return nil
}

func (store *MetaDataStore) Close() error {
	return store.db.Close()
}

func (store *MetaDataStore) CreateClusterMeta(clusterID string, meta ClusterMeta) error {
	clusterKey := []byte(fmt.Sprintf("cluster-%s", clusterID))

	metaBytes, err := store.serializeMeta(meta)
	if err != nil {
		return err
	}

	err = store.db.Update(func(txn *badger.Txn) error {
		_, err := txn.Get(clusterKey)
		if err == nil {
			return errors.New("cluster meta-data already existed")
		}

		err = txn.Set(clusterKey, metaBytes)
		return err
	})
	if err != nil {
		return err
	}

	return nil
}

type UpdateClusterMetaFunc func(ClusterMeta) (ClusterMeta, error)

func (store *MetaDataStore) UpdateClusterMeta(clusterID string, updateFunc UpdateClusterMetaFunc) error {
	clusterKey := []byte(fmt.Sprintf("cluster-%s", clusterID))
	return store.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get(clusterKey)
		if err != nil {
			return err
		}

		metaBytes, err := item.Value()
		if err != nil {
			return err
		}

		meta, err := store.deserializeMeta(metaBytes)
		if err != nil {
			return err
		}

		meta, err = updateFunc(meta)
		if err != nil {
			return err
		}

		metaBytes, err = store.serializeMeta(meta)
		if err != nil {
			return err
		}

		err = txn.Set(clusterKey, metaBytes)
		if err != nil {
			return err
		}

		return nil
	})
}

func (store *MetaDataStore) GetClusterMeta(clusterID string) (ClusterMeta, error) {
	clusterKey := []byte(fmt.Sprintf("cluster-%s", clusterID))

	var meta ClusterMeta
	// dgraph-io/badger sometimes panicing
	defer func() {
		if r := recover(); r != nil {
			glog.Warningf("Something went wrong while retrieving cluster meta")
			return
		}
	}()
	err := store.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get(clusterKey)
		if err != nil {
			return err
		}

		metaBytes, err := item.Value()
		if err != nil {
			return err
		}

		meta, err = store.deserializeMeta(metaBytes)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return DEFAULT_CLUSTER_META, err
	}

	return meta, nil
}
