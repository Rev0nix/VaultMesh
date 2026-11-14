terraform {
  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "ap-south-1"
}

# 1. VPC for VaultMesh Enterprise Deployment
resource "aws_vpc" "vaultmesh_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "vaultmesh-production-vpc"
    Environment = "MajorProject"
  }
}

# 2. Public Subnet
resource "aws_subnet" "vaultmesh_subnet" {
  vpc_id                  = aws_vpc.vaultmesh_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name = "vaultmesh-public-subnet"
  }
}

# 3. Security Group for CSPM Scanner & Backend
resource "aws_security_group" "vaultmesh_sg" {
  name        = "vaultmesh-backend-sg"
  description = "Security group for VaultMesh container nodes"
  vpc_id      = aws_vpc.vaultmesh_vpc.id

  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow inbound API traffic"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "vaultmesh-sg"
  }
}

output "vpc_id" {
  value = aws_vpc.vaultmesh_vpc.id
}

output "security_group_id" {
  value = aws_security_group.vaultmesh_sg.id
}