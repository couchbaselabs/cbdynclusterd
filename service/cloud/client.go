package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/couchbaselabs/cbdynclusterd/store"
	"io"
	"io/ioutil"
	"net/http"
	"sync"
)

// Totally not stolen from https://github.com/couchbasecloud/rest-api-examples/blob/main/go/client/client.go

const (
	headerKeyTimestamp     = "Couchbase-Timestamp"
	headerKeyAuthorization = "Authorization"
	headerKeyContentType   = "Content-Type"
)

type client struct {
	httpClient *http.Client

	jwts map[string]map[string]string
	mu   sync.Mutex
}

func NewClient() *client {
	return &client{
		httpClient: http.DefaultClient,
		jwts:       make(map[string]map[string]string),
	}
}

func (c *client) createRequest(ctx context.Context, method, uri string, body interface{}) (*http.Request, error) {
	var bb io.Reader

	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal body: %w", err)
		}

		bb = bytes.NewReader(b)
	}

	r, err := http.NewRequestWithContext(ctx, method, uri, bb)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	r.Header.Add(headerKeyContentType, "application/json")

	return r, nil
}

func (c *client) Do(ctx context.Context, method, uri string, body interface{}, env *store.CloudEnvironment) (*http.Response, error) {
	r, err := c.createRequest(ctx, method, env.BaseURLPublic()+uri, body)
	if err != nil {
		return nil, err
	}

	bearer := fmt.Sprintf("Bearer %s", env.SecretKey)
	r.Header.Set(headerKeyAuthorization, bearer)

	return c.httpClient.Do(r)
}

func (c *client) doInternal(ctx context.Context, method, uri string, body interface{}, forceRefreshJwt bool, env *store.CloudEnvironment) (*http.Response, error) {
	r, err := c.createRequest(ctx, method, env.BaseURLInternal()+uri, body)
	if err != nil {
		return nil, err
	}

	jwt, err := c.fetchJwt(ctx, env, forceRefreshJwt)
	if err != nil {
		return nil, err
	}

	bearer := "Bearer " + jwt
	r.Header.Add(headerKeyAuthorization, bearer)

	resp, err := c.httpClient.Do(r)
	if err != nil {
		return nil, err
	}

	// If we force refresh jwt and still get auth error then the credentials are probably wrong so prevent looping forever
	if resp.StatusCode == 401 && !forceRefreshJwt {
		return c.doInternal(ctx, method, uri, body, true, env)
	}

	return resp, nil
}

func (c *client) DoInternal(ctx context.Context, method, uri string, body interface{}, env *store.CloudEnvironment) (*http.Response, error) {
	return c.doInternal(ctx, method, uri, body, false, env)
}

// Lock must be held
func (c *client) setJwt(env *store.CloudEnvironment, jwt string) {
	if tenant, ok := c.jwts[env.TenantID]; ok {
		tenant[env.ProjectID] = jwt
	} else {
		c.jwts[env.TenantID] = map[string]string{
			env.ProjectID: jwt,
		}
	}
}

// Lock must be held
func (c *client) getJwt(env *store.CloudEnvironment) string {
	if tenant, exists := c.jwts[env.TenantID]; exists {
		return tenant[env.ProjectID]
	}
	return ""
}

func (c *client) fetchJwt(ctx context.Context, env *store.CloudEnvironment, forceRefresh bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.getJwt(env) == "" || forceRefresh {
		r, err := c.createRequest(ctx, "POST", env.BaseURLInternal()+sessionsPath, nil)
		if err != nil {
			return "", err
		}

		r.SetBasicAuth(env.Username, env.Password)

		res, err := c.httpClient.Do(r)
		if err != nil {
			return "", err
		}

		if res.StatusCode < 200 || res.StatusCode >= 300 {
			bb, err := ioutil.ReadAll(res.Body)
			if err != nil {
				return "", fmt.Errorf("create session failed: reason could not be determined: %v", err)
			}
			return "", fmt.Errorf("create session failed: %s", string(bb))
		}

		bb, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return "", err
		}

		var respBody sessionsResponse
		if err := json.Unmarshal(bb, &respBody); err != nil {
			return "", err
		}

		c.setJwt(env, respBody.Jwt)
	}

	return c.getJwt(env), nil
}
