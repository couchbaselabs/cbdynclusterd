packer {
  required_plugins {
    amazon = {
      version = ">= 0.0.2"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "download_username" {
  type    = string
  default = "couchbase"
}

variable "download_password" {
  type      = string
  sensitive = true
}

variable "build_pkg" {
  type = string
}

variable "base_url" {
  type = string
}

variable "version" {
  type = string
}

variable "arch" {
  type    = string
  default = "x86_64"
}

variable "ami_name" {
  type = string
}

variable "source_ami_filter" {
  type = string
}

source "amazon-ebs" "amzn2" {
  ami_name      = var.ami_name
  instance_type = var.arch == "aarch64" ? "t4g.micro" : "t2.micro"
  source_ami_filter {
    filters = {
      name                = var.source_ami_filter
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    most_recent = true
    owners      = ["amazon"]
  }
  ssh_username          = "ec2-user"
  force_deregister      = true
  force_delete_snapshot = true
  launch_block_device_mappings {
    device_name           = "/dev/xvda"
    volume_size           = 40
    volume_type           = "gp2"
    delete_on_termination = true
  }
  snapshot_tags = {
    linked_ami = var.ami_name
  }
}

build {
  sources = [
    "source.amazon-ebs.amzn2"
  ]
  provisioner "shell" {
    inline = [
      "curl -u ${var.download_username}:${var.download_password} -o ${var.build_pkg} -s ${local.build_url}",
      "sudo yum install -y ${var.build_pkg}",
      "rm ${var.build_pkg}",
    ]
  }
}

locals {
  build_url = "${var.base_url}/${var.build_pkg}"
}
