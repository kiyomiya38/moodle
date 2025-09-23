terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
  }
  required_version = ">= 1.6.0"
}

provider "aws" {
  region = var.region
}

# --- Data sources ---
data "aws_availability_zones" "azs" {
  state = "available"
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  name = var.project_name
  tags = {
    Project = var.project_name
  }
}

# --- Networking (simple 1-AZ public) ---
resource "aws_vpc" "main" {
  cidr_block           = "10.81.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = "${local.name}-vpc" })
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = merge(local.tags, { Name = "${local.name}-igw" })
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.81.10.0/24"
  availability_zone       = data.aws_availability_zones.azs.names[0]
  map_public_ip_on_launch = true
  tags                    = merge(local.tags, { Name = "${local.name}-public-subnet" })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = merge(local.tags, { Name = "${local.name}-public-rt" })
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# --- Security Groups ---
# Workstation: SSH from operator only
resource "aws_security_group" "ws" {
  name        = "${local.name}-ws-sg"
  description = "Allow SSH from my_ip_cidr"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.name}-ws-sg" })
}

# Moodle: HTTP/HTTPS from anywhere, SSH from workstation SG
resource "aws_security_group" "moodle" {
  name        = "${local.name}-moodle-sg"
  description = "Allow HTTP/HTTPS from internet, SSH from WS"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description     = "SSH from workstation"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.ws.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.tags, { Name = "${local.name}-moodle-sg" })
}

# --- SSM Parameter (store your PEM so WS can fetch it) ---
resource "aws_ssm_parameter" "ws_private_key" {
  name        = var.ssm_param_name
  description = "PEM content for ${var.key_name} to be placed on WS"
  type        = "SecureString"
  value       = var.test_key_pem
  tags        = local.tags
}

# --- IAM for Workstation (allow SSM GetParameter + EC2 Describe*) ---
resource "aws_iam_role" "ws_role" {
  name               = "${local.name}-ws-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "ws_inline" {
  name = "${local.name}-ws-policy"
  role = aws_iam_role.ws_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameter", "ssm:GetParameters"]
        Resource = aws_ssm_parameter.ws_private_key.arn
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "ssm.${var.region}.amazonaws.com"
          }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["ec2:DescribeInstances", "ec2:DescribeTags"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ws_profile" {
  name = "${local.name}-ws-profile"
  role = aws_iam_role.ws_role.name
  tags = local.tags
}

# --- Instances ---
# Moodle Server（先に作って、WS の user_data に PrivateIP を埋め込む）
resource "aws_instance" "moodle" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.moodle_instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.moodle.id]
  key_name                    = var.key_name
  associate_public_ip_address = true

  root_block_device {
    volume_type = "gp3"
    volume_size = var.moodle_disk_size_gb
  }

  user_data = <<-EOF
              #!/bin/bash
              set -euxo pipefail
              export DEBIAN_FRONTEND=noninteractive
              apt-get update -y
              apt-get install -y unzip curl jq
              echo "Moodle target node. Provision me with Ansible." > /etc/motd
              EOF

  tags = merge(local.tags, { Name = "${local.name}-moodle" })
}

# Workstation
resource "aws_instance" "workstation" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.ws_instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.ws.id]
  key_name                    = var.key_name
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.ws_profile.name

  root_block_device {
    volume_type = "gp3"
    volume_size = var.ws_disk_size_gb
  }

  # 完全自動化：PEM取得・Ansible導入・SSHエントリ作成（Host moodle は PrivateIP 指定）
  user_data = <<-EOF
              #!/bin/bash
              set -euxo pipefail
              export DEBIAN_FRONTEND=noninteractive

              # 基本ツール（失敗しても続行）
              apt-get update -y || true
              apt-get install -y curl unzip jq git make build-essential python3-pip python3-venv || true

              # Ubuntu 24.04 では apt の awscli が無いことがある → snap で導入（失敗しても続行）
              snap install aws-cli --classic || true
              ln -s /snap/bin/aws /usr/local/bin/aws 2>/dev/null || true

              # ~/.ssh 準備
              sudo -u ubuntu mkdir -p /home/ubuntu/.ssh
              chmod 700 /home/ubuntu/.ssh
              chown -R ubuntu:ubuntu /home/ubuntu/.ssh

              # SSM から PEM を取得（最大5回リトライ）
              for i in 1 2 3 4 5; do
                set +e
                aws ssm get-parameter --name "${var.ssm_param_name}" --with-decryption --query Parameter.Value --output text > /home/ubuntu/.ssh/test-key.pem
                rc=$?
                set -e
                [ "$rc" -eq 0 ] && break || sleep 3
              done
              chown ubuntu:ubuntu /home/ubuntu/.ssh/test-key.pem || true
              chmod 600 /home/ubuntu/.ssh/test-key.pem || true

              # Ansible（任意・失敗しても続行）
              apt-get install -y ansible || true
              sudo -u ubuntu ansible-galaxy collection install community.mysql || true

              # SSH config（必ず作る）
              cat >/home/ubuntu/.ssh/config <<CFG
              Host moodle
                HostName ${aws_instance.moodle.private_ip}
                User ubuntu
                IdentityFile /home/ubuntu/.ssh/test-key.pem
                StrictHostKeyChecking accept-new
                UserKnownHostsFile=/home/ubuntu/.ssh/known_hosts
              CFG
              chown ubuntu:ubuntu /home/ubuntu/.ssh/config || true
              chmod 600 /home/ubuntu/.ssh/config || true

              # known_hosts 事前登録（ベストエフォート）
              sudo -u ubuntu ssh-keyscan -T 5 ${aws_instance.moodle.private_ip} >> /home/ubuntu/.ssh/known_hosts || true

              echo "Workstation ready. Try: ssh moodle" > /etc/motd
              EOF

  # 明示的に順序を保証（Moodle の PrivateIP を参照しているため自動依存するが、念のため）
  depends_on = [aws_instance.moodle]

  tags = merge(local.tags, { Name = "${local.name}-workstation" })
}

# --- Outputs ---
output "vpc_id"               { value = aws_vpc.main.id }
output "public_subnet_id"     { value = aws_subnet.public.id }
output "workstation_public_ip"{ value = aws_instance.workstation.public_ip }
output "moodle_public_ip"     { value = aws_instance.moodle.public_ip }
output "moodle_private_ip"    { value = aws_instance.moodle.private_ip }
output "moodle_url_http"      { value = "http://${aws_instance.moodle.public_ip}/" }
output "workstation_ssh"      { value = "ssh -i test-key.pem ubuntu@${aws_instance.workstation.public_ip}" }
output "moodle_ssh_from_ws"   { value = "ssh moodle" }
