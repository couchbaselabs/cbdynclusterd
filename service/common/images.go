package common

import (
	"fmt"
	"github.com/pkg/errors"
	"net/http"
)

func CheckBuildExists(versionInfo *NodeVersion) error {
	url := fmt.Sprintf("%s/%s", versionInfo.ToURL(), versionInfo.ToPkgName())
	resp, err := http.Head(url)
	if err != nil {
		return errors.Wrap(err, "Could not locate build")
	}
	if resp.StatusCode != 200 {
		return errors.New("Could not locate build")
	}

	return nil
}
