package docker

import (
	"errors"
	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/go-git/go-git/v5"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
)

type Products map[string]map[string]AliasVersion

type AliasVersion struct {
	Release string `yaml:"release,omitempty"`
	Stable  string `yaml:"stable,omitempty"`
}

//Returns the product map from the local products yaml file
func (ds *DockerService) getProductsMap() (Products, error) {
	yamlFile, err := ioutil.ReadFile(ds.aliasRepoPath + "/" + helper.AliasFileName)
	if err != nil {
		log.Printf("Read file err   #%v ", err)
		return nil, err
	}
	return parseYaml(yamlFile)
}

func parseYaml(data []byte) (Products, error) {
	var products Products
	err := yaml.Unmarshal(data, &products)
	if err != nil {
		return nil, err
	}
	return products, nil
}

//Clones/pulls the github alias repo
func (ds *DockerService) getConfigRepo() error {
	log.Printf("Cloning products repo to %s", ds.aliasRepoPath)
	_, err := git.PlainClone(ds.aliasRepoPath, false, &git.CloneOptions{
		URL:      helper.AliasRepo,
		Progress: os.Stdout,
	})

	if errors.Is(err, git.ErrRepositoryAlreadyExists) {
		return ds.pullConfigRepo()
	}
	return err
}

func (ds *DockerService) pullConfigRepo() error {
	r, err := git.PlainOpen(ds.aliasRepoPath)
	if err != nil {
		return err
	}

	w, err := r.Worktree()
	if err != nil {
		return err
	}

	log.Printf("Pulling products repo")
	err = w.Pull(&git.PullOptions{RemoteName: "origin"})
	if errors.Is(err, git.NoErrAlreadyUpToDate) {
		log.Printf("%v", err)
		return nil
	}
	return err
}
