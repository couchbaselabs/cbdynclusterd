package common

import (
	"errors"
	"io/ioutil"
	"log"
	"os"

	"github.com/couchbaselabs/cbdynclusterd/helper"
	"github.com/go-git/go-git/v5"
	"gopkg.in/yaml.v2"
)

type Products map[string]map[string]AliasVersion

type AliasVersion struct {
	Release string `yaml:"release,omitempty"`
	Stable  string `yaml:"stable,omitempty"`
}

//Returns the product map from the local products yaml file
func getProductsMap(aliasRepoPath string) (Products, error) {
	yamlFile, err := ioutil.ReadFile(aliasRepoPath + "/" + helper.AliasFileName)
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
func GetConfigRepo(aliasRepoPath string) error {
	log.Printf("Cloning products repo to %s", aliasRepoPath)
	_, err := git.PlainClone(aliasRepoPath, false, &git.CloneOptions{
		URL:      helper.AliasRepo,
		Progress: os.Stdout,
	})

	if errors.Is(err, git.ErrRepositoryAlreadyExists) {
		return pullConfigRepo(aliasRepoPath)
	}
	return err
}

func pullConfigRepo(aliasRepoPath string) error {
	r, err := git.PlainOpen(aliasRepoPath)
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
