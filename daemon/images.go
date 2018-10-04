package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/docker/docker/api/types"
	"github.com/jhoonb/archivex"
	"github.com/pkg/errors"
)

type imageEvent struct {
	Status         string `json:"status"`
	Error          string `json:"error"`
	Progress       string `json:"progress"`
	ProgressDetail struct {
		Current int `json:"current"`
		Total   int `json:"total"`
	} `json:"progressDetail"`
}

type imageBuildArgs struct {
	Version string
	BuildNo string
}

func imagePush(ctx context.Context, nodeVersion *NodeVersion) error {
	eventReader, err := docker.ImagePush(ctx, nodeVersion.toImageName(), types.ImagePushOptions{
		RegistryAuth: dockerRegistry,
	})
	if err != nil {
		return err
	}

	defer eventReader.Close()
	err = parseImageEvent(eventReader)
	if err != nil {
		return errors.Wrap(err, "could not push image")
	}

	return nil
}

func imageBuild(ctx context.Context, nodeVersion *NodeVersion, dockerfilePath string) error {
	tar := new(archivex.TarFile)
	tarPath := fmt.Sprintf("/tmp/%s-%s.tar", nodeVersion.Version, nodeVersion.Build)
	err := tar.Create(tarPath)
	if err != nil {
		return errors.Wrap(err, "could not create tar file")
	}
	err = tar.AddAll(dockerfilePath, false)
	if err != nil {
		return errors.Wrapf(err, "could not create add %s to tar file", dockerfilePath)
	}
	err = tar.Close()
	if err != nil {
		return errors.Wrap(err, "could not close tar file")
	}

	pkg := nodeVersion.toPkgName()
	url := nodeVersion.toURL()
	buildArgs := make(map[string]*string)
	buildArgs["VERSION"] = &nodeVersion.Version
	buildArgs["BUILD_NO"] = &nodeVersion.Build
	buildArgs["FLAVOR"] = &nodeVersion.Flavor
	buildArgs["BUILD_PKG"] = &pkg
	buildArgs["BASE_URL"] = &url

	buildCtx, err := os.Open(tarPath)
	defer buildCtx.Close()

	resp, err := docker.ImageBuild(ctx, buildCtx, types.ImageBuildOptions{
		PullParent:     true,
		Tags:           []string{nodeVersion.toImageName()},
		BuildArgs:      buildArgs,
		SuppressOutput: false,
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	err = parseImageEvent(resp.Body)
	if err != nil {
		return errors.Wrap(err, "could not build image")
	}

	return nil
}

func imagePull(ctx context.Context, imageRef string) error {
	eventReader, err := docker.ImagePull(ctx, imageRef, types.ImagePullOptions{
		All:          false,
		RegistryAuth: dockerRegistry,
	})
	if err != nil {
		return err
	}

	defer eventReader.Close()
	err = parseImageEvent(eventReader)
	if err != nil {
		return errors.Wrap(err, "could not pull image")
	}

	return nil
}

func parseImageEvent(events io.Reader) error {
	d := json.NewDecoder(events)

	var event *imageEvent
	for {
		if err := d.Decode(&event); err != nil {
			if err == io.EOF {
				break
			}

			return err
		}

		if event.Error != "" {
			return errors.New(event.Error)
		}
	}

	return nil
}
