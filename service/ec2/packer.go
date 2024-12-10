package ec2

import (
	"fmt"
	"os"
	"os/exec"
)

type PackerOptions struct {
	BuildPkg       string
	AmiName        string
	Arch           string
	OS             string
	ServerlessMode bool
}

func addArg(args *[]string, arg string) {
	*args = append(*args, "-var")
	*args = append(*args, arg)
}

type AMIArg struct {
	SourceAMIFilter string
	Owner           string
}

// os -> arch -> ami
var packageToAMIArg = map[string]map[string]AMIArg{
	"amzn2": {"aarch64": AMIArg{SourceAMIFilter: "amzn2-ami-hvm-2.0.*.1-arm64-gp2", Owner: "amazon"}, "x86_64": AMIArg{SourceAMIFilter: "amzn2-ami-hvm-2.0.*.1-x86_64-gp2", Owner: "amazon"}},
	// From https://wiki.centos.org/Cloud/AWS
	// > aws ec2 describe-images --owners aws-marketplace --filters Name=product-code,Values=cvugziknvmxgqna9noibqnnsy | jq '.Images[0].Name'
	// > "CentOS-7-2111-20220825_1.x86_64-d9a3032a-921c-4c6d-b150-bde168105e42"
	"centos7": {"x86_64": AMIArg{SourceAMIFilter: "CentOS Linux 7*", Owner: "aws-marketplace"}},
	"linux":   {"x86_64": AMIArg{SourceAMIFilter: "Rocky-9-EC2-Base-*", Owner: "aws-marketplace"}},
}

var osToSSHUsername = map[string]string{
	"amzn2":   "ec2-user",
	"centos7": "centos",
	"linux":   "rocky",
}

var osToPackerfilePrefix = map[string]string{
	"amzn2":   "yum",
	"centos7": "yum",
	"linux":   "yum",
}

var osToDeviceName = map[string]string{
	"amzn2":   "/dev/xvda",
	"centos7": "/dev/sda1",
	"linux":   "/dev/sda1",
}

func CallPacker(opts PackerOptions) error {
	filePath := fmt.Sprintf("packerfiles/aws-%s.pkr.hcl", osToPackerfilePrefix[opts.OS])

	err := exec.Command("packer", "init", filePath).Run()

	if err != nil {
		return err
	}

	args := []string{}

	args = append(args, "build")
	addArg(&args, "build_pkg="+opts.BuildPkg)
	addArg(&args, "ami_name="+opts.AmiName)
	addArg(&args, "arch="+opts.Arch)
	addArg(&args, "source_ami_filter="+packageToAMIArg[opts.OS][opts.Arch].SourceAMIFilter)
	addArg(&args, "ssh_username="+osToSSHUsername[opts.OS])
	addArg(&args, "ami_owner="+packageToAMIArg[opts.OS][opts.Arch].Owner)
	addArg(&args, "device_name="+osToDeviceName[opts.OS])
	addArg(&args, "serverless_mode="+fmt.Sprintf("%t", opts.ServerlessMode))
	args = append(args, filePath)

	cmd := exec.Command("packer", args...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()

	return err
}
