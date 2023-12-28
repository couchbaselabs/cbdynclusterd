package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/couchbaselabs/cbdynclusterd/dyncontext"
	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/couchbaselabs/cbdynclusterd/service/common"

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

func (ds *DockerService) imagePush(ctx context.Context, nodeVersion *common.NodeVersion) error {
	eventReader, err := ds.docker.ImagePush(ctx, nodeVersion.ToImageName(ds.dockerRegistry), types.ImagePushOptions{
		RegistryAuth: ds.dockerRegistry,
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

func (ds *DockerService) imageBuild(ctx context.Context, nodeVersion *common.NodeVersion, dockerfilePath string) error {
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

	pkg := nodeVersion.ToPkgName()
	url := nodeVersion.ToURL()
	buildArgs := make(map[string]*string)
	buildArgs["VERSION"] = &nodeVersion.Version
	buildArgs["BUILD_NO"] = &nodeVersion.Build
	buildArgs["FLAVOR"] = &nodeVersion.Flavor
	buildArgs["BUILD_PKG"] = &pkg
	buildArgs["BASE_URL"] = &url
	if nodeVersion.ServerlessMode {
		serverlessMode := "true"
		buildArgs["SERVERLESS_MODE"] = &serverlessMode
	}

	buildCtx, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer buildCtx.Close()

	resp, err := ds.docker.ImageBuild(ctx, buildCtx, types.ImageBuildOptions{
		PullParent:     true,
		Tags:           []string{nodeVersion.ToImageName(ds.dockerRegistry)},
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

func (ds *DockerService) imagePull(ctx context.Context, imageRef string) error {
	eventReader, err := ds.docker.ImagePull(ctx, imageRef, types.ImagePullOptions{
		All:          false,
		RegistryAuth: ds.dockerRegistry,
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

func (ds *DockerService) ensureImageExists(ctx context.Context, versionInfo *common.NodeVersion, clusterID string) error {
	containerImage := versionInfo.ToImageName(ds.dockerRegistry)
	user := dyncontext.ContextUser(ctx)
	if ds.dockerRegistry == "" {
		err := common.CheckBuildExists(versionInfo)
		if err != nil {
			return err
		}

		// If the image is already built then this will won't rebuild
		if clusterID == "" {
			log.Printf("Building %s image (requested by: %s)", containerImage, user)
		} else {
			log.Printf("Building %s image for cluster %s (requested by: %s)", containerImage, clusterID, user)
		}
		err = ds.imageBuild(ctx, versionInfo, helper.DockerFilePath+"couchbase/"+versionInfo.OS)
		if err != nil {
			return err
		}

		return nil
	}

	log.Printf("Pulling %s image for cluster %s (requested by: %s)", containerImage, clusterID, user)
	err := ds.imagePull(ctx, containerImage)
	if err != nil {
		// assume that pull failed because the image didn't exist on the registry
		// check the build exists and then build the image
		err = common.CheckBuildExists(versionInfo)
		if err != nil {
			return err
		}

		log.Printf("Building %s image for cluster %s (requested by: %s)", containerImage, clusterID, user)
		err = ds.imageBuild(ctx, versionInfo, helper.DockerFilePath+"couchbase/"+versionInfo.OS)
		if err != nil {
			return err
		}

		log.Printf("Pushing %s image for cluster %s (requested by: %s)", containerImage, clusterID, user)
		err = ds.imagePush(ctx, versionInfo)
		if err != nil {
			return err
		}
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
