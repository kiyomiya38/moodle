variable "project_name" { default = "moodle-osaka" }
variable "region"       { default = "ap-northeast-3" } # Osaka

# EC2 types
variable "ws_instance_type"     { default = "t3.medium" }
variable "moodle_instance_type" { default = "t3.xlarge" }

# 互換のため残す（未使用）
variable "key_name" { default = "test-key" }

# Disks
variable "ws_disk_size_gb"     { default = 50 }
variable "moodle_disk_size_gb" { default = 200 }

# Security
variable "my_ip_cidr" {
  description = "Allow-list CIDR for SSH to workstation (e.g., 203.0.113.10/32)"
  default     = "0.0.0.0/0"
}

# 互換のため残す（未使用）。プロンプト抑止のため default を付与。
variable "ssm_param_name" { default = "/infra/test-key-pem" }
variable "test_key_pem" {
  description = "The PEM content of the key named by var.key_name (unused)"
  type        = string
  sensitive   = true
  default     = ""
}
