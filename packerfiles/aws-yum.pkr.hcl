packer {
  required_plugins {
    amazon = {
      version = ">= 0.0.2"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "build_pkg" {
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

variable "ssh_username" {
  type = string
}

variable "ami_owner" {
  type = string
}

variable "device_name" {
  type = string
}

variable "serverless_mode" {
  type = bool
  default = false
}

locals {
  source_ami_filters = var.arch == "aarch64" ? {
    name                = var.source_ami_filter
    root-device-type    = "ebs"
    virtualization-type = "hvm"
    architecture        = "arm64"
  } : {
    name                = var.source_ami_filter
    root-device-type    = "ebs"
    virtualization-type = "hvm"
    architecture        = "x86_64"
  }
}


source "amazon-ebs" "yum" {
  ami_name      = var.ami_name
  instance_type = var.arch == "aarch64" ? "t4g.micro" : "t2.small"
  source_ami_filter {
    filters      = local.source_ami_filters
    most_recent  = true
    owners       = [var.ami_owner]
  }

  ssh_username          = var.ssh_username
  force_deregister      = true
  force_delete_snapshot = true
  launch_block_device_mappings {
    device_name           = var.device_name
    volume_size           = 40
    volume_type           = "gp3"
    delete_on_termination = true
  }
  snapshot_tags = {
    Name = var.ami_name
  }
}

build {
  sources = [
    "source.amazon-ebs.yum"
  ]
  provisioner "file" {
    destination = "/tmp/"
    source      = "/tmp/${var.build_pkg}"
  }
  provisioner "shell" {
    inline = [
      "sudo yum install -y /tmp/${var.build_pkg}",
      "rm /tmp/${var.build_pkg}",
      "sudo usermod -a -G couchbase ${var.ssh_username}",
      "sudo chmod 770 /opt/couchbase/var/lib/couchbase",
      "if [ ${var.serverless_mode} == 'true' ]; then sudo mkdir -p /etc/couchbase.d && sudo /bin/sh -c 'echo serverless > /etc/couchbase.d/config_profile' && sudo chmod 755 /etc/couchbase.d/config_profile; fi"
    ]
  }
}
