terraform {
  required_version = ">= 1.7, < 2.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.3"
    }
  }
}

variable "region" {
  description = "Commercial AWS region containing the subnet and KMS key."
  type        = string
  default     = "us-east-1"
}

variable "subnet_id" {
  description = "Existing public subnet with an Internet Gateway route; no network is created."
  type        = string
}

variable "ssh_cidr" {
  description = "Your public IPv4 address as a /32. Only SSH is exposed."
  type        = string

  validation {
    condition     = can(cidrnetmask(var.ssh_cidr)) && endswith(var.ssh_cidr, "/32")
    error_message = "Use a single IPv4 address with /32, not an open or shared network."
  }
}

variable "ssh_public_key_path" {
  description = "Local public SSH key to import into EC2; never supply a private key."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "kms_admin_role_arn" {
  description = "Same-account IAM role running Terraform; separate from the EC2 role."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/-]+$", var.kms_admin_role_arn))
    error_message = "Supply the IAM role ARN, not an STS session, user, or root ARN."
  }
}

variable "blockhash" {
  description = "Public nonzero Bitcoin block hash for this test root. Preserve it for recovery."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F]{64}$", var.blockhash)) && trim(var.blockhash, "0") != ""
    error_message = "Use a nonzero 64-hex displayed block hash."
  }
}

variable "network" {
  description = "Bitcoin network for the test root; changing it changes the root. Mainnet is refused here."
  type        = string
  default     = "regtest"

  validation {
    condition     = contains(["bitcoin", "testnet", "testnet4", "signet", "regtest"], var.network)
    error_message = "Use bitcoin, testnet, testnet4, signet, or regtest."
  }

  validation {
    condition     = var.network != "bitcoin"
    error_message = "This one-apply test setup cannot prove future-block chronology; use the manual custody procedure in USAGE.txt for mainnet."
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project = "sapio-tee-test"
    }
  }
}

data "aws_subnet" "parent" {
  id = var.subnet_id
}

data "aws_ssm_parameter" "ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

resource "aws_key_pair" "parent" {
  key_name_prefix = "sapio-tee-test-"
  public_key      = trimspace(file(pathexpand(var.ssh_public_key_path)))
}

# KMS access comes only from the measured-image key policy, never an admin grant.
# S3 downloads and Systems Manager permissions are attached separately below.
resource "aws_iam_role" "parent" {
  name_prefix = "sapio-tee-test-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_instance_profile" "parent" {
  name_prefix = "sapio-tee-test-"
  role        = aws_iam_role.parent.name
}

data "external" "build" {
  program = ["python3", "${path.module}/build.py"]
  query = {
    repository_root = abspath("${path.module}/../..")
  }
}

data "external" "key_policy" {
  program = ["python3", "${path.module}/../key-policy.py", "--terraform"]
  query = {
    admin_role_arn  = var.kms_admin_role_arn
    parent_role_arn = aws_iam_role.parent.arn
    pcr0            = data.external.build.result.pcr0
  }
}

resource "aws_kms_key" "oracle" {
  description              = "Sapio TEE test root; retain key and exact setup settings for recovery"
  customer_master_key_spec = "ECC_NIST_P256"
  key_usage                = "KEY_AGREEMENT"
  deletion_window_in_days  = 30
  policy                   = data.external.key_policy.result.policy

  # Deleting this key can permanently destroy the ability to recover the root.
  lifecycle {
    prevent_destroy = true
  }
}

locals {
  artifact_paths = {
    "sapio_tee.eif"         = data.external.build.result.eif_path
    "enclaver"              = data.external.build.result.runner_path
    "enclaver.yaml"         = "${path.module}/../../enclaver.yaml"
    "deploy/run-enclave.py" = "${path.module}/../run-enclave.py"
    "deploy/initialize.py"  = "${path.module}/../initialize.py"
    "sapio-tee.service"     = "${path.module}/sapio-tee.service"
  }
  artifact_hashes = { for name, path in local.artifact_paths : name => filesha256(path) }
  setup_json = jsonencode({
    key_id    = aws_kms_key.oracle.arn
    blockhash = lower(var.blockhash)
    network   = var.network
  })
  # Content-addressed uploads prevent a boot from mixing old and new artifacts.
  deployment_hash = sha256(jsonencode({
    artifacts = local.artifact_hashes
    setup     = sha256(local.setup_json)
  }))
}

resource "aws_s3_bucket" "artifacts" {
  bucket_prefix = "sapio-tee-test-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "artifacts" {
  for_each = local.artifact_paths

  bucket      = aws_s3_bucket.artifacts.id
  key         = "${local.deployment_hash}/${each.key}"
  source      = each.value
  source_hash = local.artifact_hashes[each.key]

  depends_on = [aws_s3_bucket_public_access_block.artifacts]
}

resource "aws_s3_object" "setup" {
  bucket       = aws_s3_bucket.artifacts.id
  key          = "${local.deployment_hash}/setup.json"
  content      = local.setup_json
  content_type = "application/json"
  source_hash  = sha256(local.setup_json)

  depends_on = [aws_s3_bucket_public_access_block.artifacts]
}

resource "aws_iam_role_policy" "artifacts" {
  name_prefix = "sapio-tee-artifacts-"
  role        = aws_iam_role.parent.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:GetObject"
      Resource = "${aws_s3_bucket.artifacts.arn}/*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.parent.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_security_group" "parent" {
  name_prefix = "sapio-tee-test-"
  description = "SSH from the operator only; use tunnels for the enclave APIs"
  vpc_id      = data.aws_subnet.parent.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = aws_security_group.parent.id
  description       = "Operator SSH and local port forwards"
  cidr_ipv4         = var.ssh_cidr
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
}

resource "aws_vpc_security_group_egress_rule" "parent" {
  security_group_id = aws_security_group.parent.id
  description       = "Package installation and public AWS endpoints"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_instance" "parent" {
  ami                         = nonsensitive(data.aws_ssm_parameter.ami.value)
  instance_type               = "m7g.xlarge"
  subnet_id                   = data.aws_subnet.parent.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.parent.id]
  key_name                    = aws_key_pair.parent.key_name
  iam_instance_profile        = aws_iam_instance_profile.parent.name

  enclave_options {
    enabled = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = true
    delete_on_termination = true
  }

  user_data = templatefile("${path.module}/bootstrap.sh.tftpl", {
    region       = var.region
    bucket       = aws_s3_bucket.artifacts.id
    prefix       = local.deployment_hash
    artifacts    = local.artifact_hashes
    setup_sha256 = sha256(local.setup_json)
  })
  user_data_replace_on_change = true

  # All artifacts, permissions and the restrictive KMS policy must precede boot.
  depends_on = [
    aws_vpc_security_group_egress_rule.parent,
    aws_iam_role_policy.artifacts,
    aws_iam_role_policy_attachment.ssm,
    aws_s3_object.artifacts,
    aws_s3_object.setup,
  ]

  tags = {
    Name = "sapio-tee-test"
  }
}

resource "terraform_data" "ready" {
  triggers_replace = [
    aws_instance.parent.id,
    filesha256("${path.module}/../wait-ready.py"),
  ]

  # Wait for an actual successful command on this exact instance. An SSM
  # association's aggregate status can precede registration of its targets.
  provisioner "local-exec" {
    working_dir = "${path.module}/.."
    command     = "python3 wait-ready.py"
    environment = {
      AWS_REGION        = var.region
      SAPIO_INSTANCE_ID = aws_instance.parent.id
      SAPIO_SETUP_JSON  = local.setup_json
    }
  }
}

output "kms_key_arn" {
  description = "Keep this exact key ARN and its material for root recovery."
  value       = aws_kms_key.oracle.arn
}

output "recovery_settings" {
  description = "Public setup record; save alongside verified identity and measurements."
  value       = jsondecode(local.setup_json)
}

output "measurements" {
  description = "PCRs emitted by the local image build, not supplied by the parent."
  value = {
    PCR0 = data.external.build.result.pcr0
    PCR1 = data.external.build.result.pcr1
    PCR2 = data.external.build.result.pcr2
  }
}

output "public_ip" {
  description = "Ephemeral address; refresh after a stop/start."
  value       = aws_instance.parent.public_ip
}

output "instance_id" {
  value = aws_instance.parent.id
}

output "parent_role_arn" {
  description = "Instance role admitted by the PCR-bound key policy."
  value       = aws_iam_role.parent.arn
}

output "ssh_tunnel" {
  description = "Use the private SSH key corresponding to ssh_public_key_path."
  value       = "ssh -o ExitOnForwardFailure=yes -N -L 127.0.0.1:8000:127.0.0.1:8000 -L 127.0.0.1:8367:127.0.0.1:8367 ec2-user@${aws_instance.parent.public_ip}"
}
