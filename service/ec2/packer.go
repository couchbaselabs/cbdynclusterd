package ec2

import (
	"fmt"
	"os"
	"os/exec"
)

type PackerOptions struct {
	DownloadPassword string
	Version          string
	BuildPkg         string
	BaseUrl          string
	AmiName          string
	Arch             string
	OS               string
}

func addArg(args *[]string, arg string) {
	*args = append(*args, "-var")
	*args = append(*args, arg)
}

// os -> arch -> ami
var packageToSourceAMIFilter = map[string]map[string]string{
	"amzn2": {"aarch64": "amzn2-ami-hvm-2.0.*.1-arm64-gp2", "x86_64": "amzn2-ami-hvm-2.0.*.1-x86_64-gp2"},
}

func CallPacker(opts PackerOptions) error {
	err := exec.Command("packer", "init", "packerfiles").Run()

	if err != nil {
		return err
	}

	args := []string{}

	args = append(args, "build")
	addArg(&args, "download_password="+opts.DownloadPassword)
	addArg(&args, "version="+opts.Version)
	addArg(&args, "build_pkg="+opts.BuildPkg)
	addArg(&args, "base_url="+opts.BaseUrl)
	addArg(&args, "ami_name="+opts.AmiName)
	addArg(&args, "arch="+opts.Arch)
	addArg(&args, "source_ami_filter="+packageToSourceAMIFilter[opts.OS][opts.Arch])
	args = append(args, fmt.Sprintf("packerfiles/aws-%s.pkr.hcl", opts.OS))

	cmd := exec.Command("packer", args...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()

	return err
}
