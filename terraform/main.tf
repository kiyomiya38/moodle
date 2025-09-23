terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
  required_version = ">= 1.6.0"
}

provider "aws" {
  region = var.region
}

# =========================
# Data sources
# =========================
data "aws_availability_zones" "azs" {
  state = "available"
}

# Ubuntu 24.04 LTS (amd64, hvm, ebs-gp3) の最新AMIをSSMから取得
data "aws_ssm_parameter" "ubuntu_2404_amd64_gp3" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

# =========================
# Locals
# =========================
locals {
  name = var.project_name
  tags = {
    Project = var.project_name
  }
}

# =========================
# SSH鍵: Terraformで自動生成 → AWS登録 → ローカル保存
# =========================
resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "ssh" {
  key_name   = "${local.name}-key"
  public_key = tls_private_key.ssh.public_key_openssh
  tags       = merge(local.tags, { Name = "${local.name}-key" })
}

resource "local_file" "ssh_pem" {
  filename        = pathexpand("./keys/${local.name}.pem")
  content         = tls_private_key.ssh.private_key_pem
  file_permission = "0600"
}

# === 秘密鍵を SSM SecureString に保存（WS が取得して二段SSHに使う） ===
resource "aws_ssm_parameter" "ssh_pem" {
  name  = "/infra/${local.name}/ssh_private_key_pem"
  type  = "SecureString"
  value = tls_private_key.ssh.private_key_pem
  tags  = merge(local.tags, { Name = "${local.name}-ssh-pem" })
}

# =========================
# IAM: Workstation が SSM から鍵を取得できるようにする
# =========================
data "aws_iam_policy_document" "ws_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ws" {
  name               = "${local.name}-ws-role"
  assume_role_policy = data.aws_iam_policy_document.ws_assume.json
  tags               = local.tags
}

# 必要最小限: GetParameter(with decryption) のみ許可
data "aws_iam_policy_document" "ws_policy" {
  statement {
    sid     = "AllowGetKeyFromSSM"
    actions = ["ssm:GetParameter"]
    resources = [
      aws_ssm_parameter.ssh_pem.arn
    ]
  }
  statement {
    sid       = "AllowDecryptSecureString"
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ssm.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "ws_inline" {
  name   = "${local.name}-ws-ssm-policy"
  role   = aws_iam_role.ws.id
  policy = data.aws_iam_policy_document.ws_policy.json
}

resource "aws_iam_instance_profile" "ws" {
  name = "${local.name}-ws-profile"
  role = aws_iam_role.ws.name
}

# =========================
# Networking
# =========================
resource "aws_vpc" "main" {
  cidr_block           = "10.81.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
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

# =========================
# Security Groups
# =========================
# Workstation: SSHのみ（操作者のIPから）
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

# Moodle: HTTP/HTTPS 全開放 + SSH は Workstation の SG からのみ
resource "aws_security_group" "moodle" {
  name        = "${local.name}-moodle-sg"
  description = "Allow HTTP/HTTPS from 0.0.0.0/0 and SSH from Workstation SG"
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

  # WS SG からのSSHのみ許可（CIDRではなく SG 参照）
  ingress {
    description     = "SSH from Workstation SG"
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

# =========================
# EC2: Moodle
# =========================
resource "aws_instance" "moodle" {
  ami                         = data.aws_ssm_parameter.ubuntu_2404_amd64_gp3.value
  instance_type               = var.moodle_instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.moodle.id]
  associate_public_ip_address = true
  key_name                    = aws_key_pair.ssh.key_name

  root_block_device {
    volume_size = var.moodle_disk_size_gb
    volume_type = "gp3"
    encrypted   = true
  }

  # --- user_data（vhost生成・有効化は撤去。Ansibleに完全委譲） ---
  user_data = <<EOF
#!/bin/bash
set -eux
export DEBIAN_FRONTEND=noninteractive

# 基本ツール
apt-get update -y
apt-get install -y nginx curl jq unzip tar apt-transport-https ca-certificates software-properties-common

# PHP（24.04は8.3）
apt-get install -y php-fpm php-cli php-curl php-xml php-zip php-gd php-intl php-mbstring php-mysql

# PHP-FPM 起動（ソケット生成）
PHPV=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
systemctl enable --now php$${PHPV}-fpm || true

# Nginx はインストールのみに留め、vhost 作成や有効化は行わない（Ansible担当）
systemctl enable --now nginx || true
EOF

  tags = merge(local.tags, { Name = "${local.name}-moodle" })
}

# =========================
# EC2: Workstation
# =========================
resource "aws_instance" "workstation" {
  ami                         = data.aws_ssm_parameter.ubuntu_2404_amd64_gp3.value
  instance_type               = var.ws_instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.ws.id]
  associate_public_ip_address = true
  key_name                    = aws_key_pair.ssh.key_name
  iam_instance_profile        = aws_iam_instance_profile.ws.name

  root_block_device {
    volume_size = var.ws_disk_size_gb
    volume_type = "gp3"
    encrypted   = true
  }

  # --- user_data（HOME対策・AWS CLI v2・鍵取得・ssh設定は維持） ---
  user_data = <<EOF
#!/bin/bash
set -eux
export DEBIAN_FRONTEND=noninteractive
export HOME=/root

# 基本ツール
apt-get update -y
apt-get install -y ca-certificates curl unzip jq build-essential make g++ git htop tmux ttyd

# ※Ansible を常設したい場合は次の1行を有効化してください
apt-get install -y ansible-core sshpass

# AWS CLI v2（Ubuntu 24.04 は apt の awscli が無い）
curl -sS "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
unzip -q /tmp/awscliv2.zip -d /tmp
/tmp/aws/install || /tmp/aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli || true
aws --version

# 学習用ユーザー
id student || useradd -m -s /bin/bash student
mkdir -p /home/student/project
chown -R student:student /home/student

# code-server
if ! command -v code-server >/dev/null 2>&1; then
  curl -fsSL https://code-server.dev/install.sh | sh
  systemctl enable --now code-server@ubuntu || true
  install -d -o ubuntu -g ubuntu /home/ubuntu/.config/code-server
  cat >/home/ubuntu/.config/code-server/config.yaml <<'CSCONF'
bind-addr: 0.0.0.0:8080
auth: none
password: ""
cert: false
CSCONF
  chown -R ubuntu:ubuntu /home/ubuntu/.config
  systemctl restart code-server@ubuntu || true
fi

# ttyd
cat >/lib/systemd/system/ttyd.service <<'TTYDUNIT'
[Unit]
Description=ttyd daemon
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/bin/ttyd -i lo -p 7681 bash
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
TTYDUNIT
systemctl daemon-reload
systemctl enable --now ttyd

# 鍵を SSM から取得して ~/.ssh/id_rsa に配置
install -d -m 0700 /home/ubuntu/.ssh
aws ssm get-parameter \
  --name "/infra/${local.name}/ssh_private_key_pem" \
  --with-decryption \
  --query 'Parameter.Value' \
  --output text > /home/ubuntu/.ssh/id_rsa
chown ubuntu:ubuntu /home/ubuntu/.ssh/id_rsa
chmod 600 /home/ubuntu/.ssh/id_rsa

# /etc/hosts に “moodle” → Private IP を登録（保険）
echo "${aws_instance.moodle.private_ip} moodle" >> /etc/hosts

# ~/.ssh/config: Host moodle → HostName に Private IP を直書き（DNS不要）
cat > /home/ubuntu/.ssh/config <<CFG
Host moodle
  HostName ${aws_instance.moodle.private_ip}
  User ubuntu
  IdentityFile /home/ubuntu/.ssh/id_rsa
  StrictHostKeyChecking accept-new
  UserKnownHostsFile /home/ubuntu/.ssh/known_hosts
CFG
chown ubuntu:ubuntu /home/ubuntu/.ssh/config
chmod 600 /home/ubuntu/.ssh/config

# known_hosts 事前登録（ベストエフォート）
sudo -u ubuntu ssh-keyscan -T 5 ${aws_instance.moodle.private_ip} >> /home/ubuntu/.ssh/known_hosts || true

# 便利エイリアス
echo "alias ll='ls -alF'" >> /etc/skel/.bashrc
echo "alias ll='ls -alF'" >> /home/ubuntu/.bashrc
EOF

  depends_on = [aws_instance.moodle]
  tags       = merge(local.tags, { Name = "${local.name}-workstation" })
}

# =========================
# Outputs
# =========================
output "vpc_id"                { value = aws_vpc.main.id }
output "public_subnet_id"      { value = aws_subnet.public.id }
output "workstation_public_ip" { value = aws_instance.workstation.public_ip }
output "moodle_public_ip"      { value = aws_instance.moodle.public_ip }
output "moodle_private_ip"     { value = aws_instance.moodle.private_ip }
output "moodle_url_http"       { value = "http://${aws_instance.moodle.public_ip}/" }

# 生成鍵でのSSH（ローカル端末→Workstation）
output "workstation_ssh" {
  value = "ssh -i ${local_file.ssh_pem.filename} ubuntu@${aws_instance.workstation.public_ip}"
}

# Workstation からは `ssh moodle` がそのまま通る
output "moodle_ssh_from_ws" {
  value = "ssh moodle"
}
