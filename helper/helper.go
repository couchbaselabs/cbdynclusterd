package helper

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

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
	RestRetry          = 60
	RestTimeout        = 60 * time.Second
	WaitTimeout        = 30 * time.Second
	restInterval       = 3 * time.Second
	SshPort            = 22
	RestPort           = 8091
	N1qlPort           = 8093
	FtsPort            = 8094
	SshUser            = "root"
	SshPass            = "couchbase"
	RestUser           = "Administrator"
	RestPass           = "password"
	BucketCouchbase    = "membase"
	BucketMemcached    = "memcached"
	BucketEphemeral    = "ephemeral"
	PPools             = "/pools"
	PRebalanceStop     = "/controller/stopRebalance"
	PPoolsNodes        = "/pools/nodes"
	PBuckets           = "/pools/default/buckets"
	PFailover          = "/controller/failOver"
	PEject             = "/controller/ejectNode"
	PSetupServices     = "/node/controller/setupServices"
	PPoolsDefault      = "/pools/default"
	PSettingsWeb       = "/settings/web"
	PRbacUsers         = "/settings/rbac/users/local"
	PAddNode           = "/controller/addNode"
	PNodesSelf         = "/nodes/self"
	PRebalance         = "/controller/rebalance"
	PRebalanceProgress = "/pools/default/rebalanceProgress"
	PSettingsIndexes   = "/settings/indexes"
	PN1ql              = "/query"
	PFts               = "/api/index"
	PRename            = "/node/controller/rename"
	PDeveloperPreview  = "/settings/developerPreview"
	PSampleBucket      = "/sampleBuckets/install"

	Domain        = "/domain"
	DomainPostfix = ".couchbase.com"

	DockerFilePath = "dockerfiles/"

	AliasRepo     = "https://github.com/couchbaselabs/cb-alias.git"
	AliasRepoPath = "/opt/cbdynclusterd/alias"
	AliasFileName = "products.yml"
)

type UserOption struct {
	Name     string
	Password string
	Roles    *[]string
}

type BucketOption struct {
	Name     string
	Type     string
	Password string
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

func Tuple(version string) (int, int, int) {
	v, err := MatchingStrings("\\s*([0-9]+).([0-9]+).([0-9,^-]+)\\s*", version)

	if err != nil {
		return 0, 0, 0
	}
	v1, _ := strconv.Atoi(v[1])
	v2, _ := strconv.Atoi(v[2])
	v3, _ := strconv.Atoi(v[3])
	return v1, v2, v3
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
	url := fmt.Sprintf("http://%s:%d%s", login.Hostname, login.Port, path)

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
