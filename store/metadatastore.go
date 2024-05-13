package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dgraph-io/badger"
	"github.com/golang/glog"
)

type ClusterPlatform string

const (
	ClusterPlatformDocker = "docker"
	ClusterPlatformCloud  = "cloud"
	ClusterPlatformEC2    = "ec2"
)

var (
	DEFAULT_CLUSTER_TIMEOUT = time.Date(2222, 1, 1, 0, 0, 0, 0, time.UTC)
	DEFAULT_CLUSTER_META    = ClusterMeta{
		Owner:    "unknown",
		Timeout:  DEFAULT_CLUSTER_TIMEOUT,
		Platform: "unknown",
	}
)

type CloudEnvironment struct {
	TenantID      string `json:"tenant_id"`
	ProjectID     string `json:"project_id"`
	URL           string `json:"url"`
	AccessKey     string `json:"access_key"`
	SecretKey     string `json:"secret_key"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	OverrideToken string `json:"override_token"`
}

func (env CloudEnvironment) BaseURLPublic() string {
	return fmt.Sprintf("https://cloudapi.%s", env.URL)
}

func (env CloudEnvironment) BaseURLInternal() string {
	return fmt.Sprintf("https://api.%s", env.URL)
}

type ClusterMetaJSON struct {
	Owner            string            `json:"owner,omitempty"`
	Timeout          string            `json:"timeout,omitempty"`
	Platform         string            `json:"platform,omitempty"`
	CloudClusterID   string            `json:"cloudClusterID,omitempty"`
	UseSecure        bool              `json:"useSecure,omitempty"`
	OS               string            `json:"os,omitempty"`
	CloudEnvironment *CloudEnvironment `json:"cloudEnvironment,omitempty"`
	CloudEnvName     string            `json:"cloudEnvName,omitempty"`
	Columnar         bool              `json:"columnar,omitempty"`
}

type ClusterMeta struct {
	Owner            string
	Timeout          time.Time
	Platform         ClusterPlatform
	CloudClusterID   string
	UseSecure        bool
	OS               string
	CloudEnvironment *CloudEnvironment
	CloudEnvName     string
	Columnar         bool
}

type MetaDataStore struct {
	db *badger.DB
}

type ReadOnlyMetaDataStore struct {
	store *MetaDataStore
}

func NewReadOnlyMetaDataStore(store *MetaDataStore) *ReadOnlyMetaDataStore {
	return &ReadOnlyMetaDataStore{
		store: store,
	}
}

func (store *ReadOnlyMetaDataStore) GetClusterMeta(clusterID string) (ClusterMeta, error) {
	return store.store.GetClusterMeta(clusterID)
}

func (store *MetaDataStore) serializeMeta(meta ClusterMeta) ([]byte, error) {
	metaJSON := ClusterMetaJSON{
		Owner:            meta.Owner,
		Timeout:          meta.Timeout.Format(time.RFC3339),
		Platform:         string(meta.Platform),
		CloudClusterID:   meta.CloudClusterID,
		UseSecure:        meta.UseSecure,
		OS:               meta.OS,
		CloudEnvironment: meta.CloudEnvironment,
		CloudEnvName:     meta.CloudEnvName,
		Columnar:         meta.Columnar,
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
		Owner:            metaJSON.Owner,
		Timeout:          parsedTimeout,
		Platform:         ClusterPlatform(metaJSON.Platform),
		CloudClusterID:   metaJSON.CloudClusterID,
		UseSecure:        metaJSON.UseSecure,
		OS:               metaJSON.OS,
		CloudEnvironment: metaJSON.CloudEnvironment,
		CloudEnvName:     metaJSON.CloudEnvName,
		Columnar:         metaJSON.Columnar,
	}, nil
}

func (store *MetaDataStore) Open(dir string) error {
	opts := badger.DefaultOptions(dir)
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

		metaBytes, err := item.ValueCopy(nil)
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
	err := store.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(clusterKey)
		if err != nil {
			return err
		}

		metaBytes, err := item.ValueCopy(nil)
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
