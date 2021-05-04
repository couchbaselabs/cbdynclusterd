package cloud

import "errors"

var (
	ErrCloudNotEnabled = errors.New("cloud is not enabled, access or private key was not set")
)
