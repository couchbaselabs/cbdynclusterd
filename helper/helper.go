package helper

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/golang/glog"
)

var (
	Slowlog                    bool
	PattActual, _              = regexp.Compile("\\s*vb_active_itm_memory:\\s*([0-9]+)")
	PattActualReplica, _       = regexp.Compile("\\s*vb_replica_itm_memory:\\s*([0-9]+)")
	PattUncompressed, _        = regexp.Compile("\\s*vb_active_itm_memory_uncompressed:\\s*([0-9]+)")
	PattUncompressedReplica, _ = regexp.Compile("\\s*vb_replica_itm_memory_uncompressed:\\s*([0-9]+)")
	SampleBucketsCount         = map[string]float64{
		"travel-sample":  31591,
		"beer-sample":    7303,
		"gamesim-sample": 586,
	}
)

const (
	RestRetry                = 60
	RestTimeout              = 60 * time.Second
	WaitTimeout              = 30 * time.Second
	restInterval             = 3 * time.Second
	SshPort                  = 22
	RestPort                 = 8091
	SecureRestPort           = 18091
	N1qlPort                 = 8093
	SecureN1qlPort           = 18093
	FtsPort                  = 8094
	SecureFtsPort            = 18094
	SshUser                  = "root"
	SshPass                  = "couchbase"
	RestUser                 = "Administrator"
	RestPass                 = "password"
	RestPassCapella          = "P@ssword1"
	BucketCouchbase          = "membase"
	BucketMemcached          = "memcached"
	BucketEphemeral          = "ephemeral"
	PPools                   = "/pools"
	PRebalanceStop           = "/controller/stopRebalance"
	PPoolsNodes              = "/pools/nodes"
	PBuckets                 = "/pools/default/buckets"
	PStats                   = "/pools/default/stats/range"
	PFailover                = "/controller/failOver"
	PEject                   = "/controller/ejectNode"
	PSetupServices           = "/node/controller/setupServices"
	ClusterInit              = "/clusterInit"
	PPoolsDefault            = "/pools/default"
	PSettingsWeb             = "/settings/web"
	PRbacUsers               = "/settings/rbac/users/local"
	PAddNode                 = "/controller/addNode"
	PNodesSelf               = "/nodes/self"
	PRebalance               = "/controller/rebalance"
	PRebalanceProgress       = "/pools/default/rebalanceProgress"
	PSettingsIndexes         = "/settings/indexes"
	PN1ql                    = "/query"
	PFts                     = "/api/index"
	PRename                  = "/node/controller/rename"
	PDeveloperPreview        = "/settings/developerPreview"
	PSampleBucket            = "/sampleBuckets/install"
	PSetupNetConfig          = "/node/controller/setupNetConfig"
	PDisableExternalListener = "/node/controller/disableExternalListener"
	PEnableExternalListener  = "/node/controller/enableExternalListener"
	PSecurity                = "/settings/security"
	PInternalSettings        = "/internalSettings"
	PAutoFailover            = "/settings/autoFailover"

	Domain        = "/domain"
	DomainPostfix = ".couchbase.com"

	DockerFilePath = "dockerfiles/"

	AliasRepo     = "https://github.com/couchbaselabs/cb-alias.git"
	AliasRepoPath = "/opt/cbdynclusterd/alias"
	AliasFileName = "products.yml"

	FtsDefaultMemoryQuota = 1024

	CapellaRoles = "query_manage_functions[*],query_manage_external_functions[*],scope_admin[*],data_writer[*],query_update[*],query_insert[*],query_delete[*],query_manage_index[*],fts_admin[*],query_manage_global_functions,query_manage_global_external_functions"
)

type UserOption struct {
	Name     string
	Password string
	Roles    *[]string
}

type BucketOption struct {
	Name           string
	Type           string
	Password       string
	StorageBackend string
}

type stop struct {
	error
}

type SubFields struct {
	SubValue       string
	RecurringField string
}

type KvData struct {
	PropValue string
	SubFields SubFields
}

type MemUsedStats struct {
	Uncompressed int
	Used         int
}

func (m *MemUsedStats) Diff() int {
	return m.Uncompressed - m.Used
}

type Cred struct {
	Username string
	Password string
	Hostname string
	Port     int
	Roles    *[]string
	Secure   bool
	KeyPath  string
}

type RestCall struct {
	ExpectedCode int
	RetryOnCode  int
	Method       string
	Path         string
	Cred         *Cred
	Body         string
	Header       map[string]string
	ContentType  string
}

func NewRandomClusterID() string {
	uuid, _ := uuid.NewRandom()
	return uuid.String()[0:8]
}

func RestRetryer(retry int, params *RestCall, fn func(*RestCall) (string, error)) (string, error) {
	var body string
	var err error
	if body, err = fn(params); err != nil {
		if s, ok := err.(stop); ok {
			return "", s.error
		}

		if retry--; retry > 0 {
			glog.Infof("Retrying %v %d more times in 1 sec", fn, retry)
			time.Sleep(restInterval)
			return RestRetryer(retry, params, fn)
		}
		return "", err
	}
	return body, nil
}

type VersionTuple struct {
	Major int
	Minor int
	Patch int
}

func (v *VersionTuple) String() string {
	return fmt.Sprintf("%d-%d-%d", v.Major, v.Minor, v.Patch)
}

func Tuple(version string) VersionTuple {
	v := strings.Split(version, "-")[0]
	parsed := strings.Split(v, ".")

	if len(parsed) != 3 {
		return VersionTuple{Major: 0, Minor: 0, Patch: 0}
	}

	major, _ := strconv.Atoi(parsed[0])
	minor, _ := strconv.Atoi(parsed[1])
	patch, _ := strconv.Atoi(parsed[2])

	return VersionTuple{Major: major, Minor: minor, Patch: patch}
}

func GetResponse(params *RestCall) (string, error) {
	expected := params.ExpectedCode
	retryOnCode := params.RetryOnCode
	method := params.Method
	path := params.Path
	login := params.Cred
	postBody := params.Body
	header := params.Header

	client := &http.Client{Timeout: RestTimeout}

	if login.Secure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	protocol := "http"
	if login.Secure {
		protocol = "https"
	}

	url := fmt.Sprintf("%s://%s:%d%s", protocol, login.Hostname, login.Port, path)

	req, err := http.NewRequest(method, url, strings.NewReader(postBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(login.Username+":"+login.Password)))
	contentType := "application/x-www-form-urlencoded"
	if params.ContentType != "" {
		contentType = params.ContentType
	}
	req.Header.Set("Content-Type", contentType)
	for k, v := range header {
		req.Header.Set(k, v)
	}

	glog.Infof("request:%s", req.URL.Path)
	res, err := client.Do(req)
	if err != nil {
		glog.Infof("Server might not be ready yet.:%s", err)
		return "", err
	}
	defer res.Body.Close()

	s := res.StatusCode
	switch {
	case s == expected:
		glog.Infof("%s returned %d", url, s)
		respBody, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return "", err
		}
		return string(respBody), nil
	case s == retryOnCode: // expected response when server is not ready for this request yet
		glog.Infof("%s returned %d which is expected when server is not ready yet", url, s)
		respBody, _ := ioutil.ReadAll(res.Body)
		return "", errors.New(string(respBody))
	default:
		respBody, err := ioutil.ReadAll(res.Body)
		glog.Infof("respBody=%s, err=%s", string(respBody), err)
		return "", stop{fmt.Errorf("Request:%v,PostBody:%s,Response:%d:%s", req, postBody, s, string(respBody))}
	}
}

func MatchingString(pattern string, str string) (string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		msg := fmt.Sprintf("Cannot compile regular expression %s", re)
		return "", errors.New(msg)
	}
	matched := re.FindStringSubmatch(str)
	if matched != nil {
		return matched[1], nil
	} else {
		return "", errors.New("No matches found")
	}
}

func MatchingStrings(pattern string, str string) ([]string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		msg := fmt.Sprintf("Cannot compile regular expression %s", re)
		return nil, errors.New(msg)
	}
	return re.FindStringSubmatch(str), nil

}

func GetRestPort(secure bool) int {
	if secure {
		return SecureRestPort
	} else {
		return RestPort
	}
}

func GetN1qlPort(secure bool) int {
	if secure {
		return SecureN1qlPort
	} else {
		return N1qlPort
	}
}

func GetFtsPort(secure bool) int {
	if secure {
		return SecureFtsPort
	} else {
		return FtsPort
	}
}
