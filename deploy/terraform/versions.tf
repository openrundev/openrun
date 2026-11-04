terraform {
  required_version = ">= 1.14.3"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.71.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 3.4.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 3.3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.9.1"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.4.2"
    }
    cloudinit = {
      source  = "hashicorp/cloudinit"
      version = "~> 2.4.1"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.14.2"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.3.2"
    }
  }
}
