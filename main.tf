terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    acme = {
      source  = "vancluever/acme"
      version = "~> 2.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.region
}

provider "acme" {
  server_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
}

# --- Data Sources to capture the latest Ubuntu AMI ---
data "aws_ami" "ubuntu_noble" {
  most_recent = true

  owners = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

locals {
  subnet_id = data.aws_subnets.default.ids[0]
}


# --- IAM Role for SSM ---
resource "aws_iam_role" "ssm" {
  name = "${var.name}-ssm-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm" {
  name = "${var.name}-instance-profile"
  role = aws_iam_role.ssm.name
}

# --- Security Group (HTTP Only) ---
resource "aws_security_group" "web" {
  name        = "${var.name}-sg"
  description = "Allow HTTP only"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "HTTP"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- EC2 Instance ---
resource "aws_instance" "this" {
  ami                         = data.aws_ami.ubuntu_noble.id
  instance_type               = var.instance_type
  subnet_id                   = local.subnet_id
  vpc_security_group_ids      = [aws_security_group.web.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.ssm.name
  key_name                    = null

  root_block_device {
    volume_size = 100 # in GiB
    volume_type = "gp3"
    encrypted   = true # optional but recommended
  }

  user_data = templatefile("${path.module}/cloud-init.tftpl", {
    server_cert             = indent(6, acme_certificate.server.certificate_pem)
    private_key             = indent(6, acme_certificate.server.private_key_pem)
    bundle_certs            = indent(6, acme_certificate.server.issuer_pem)
    tfe_license             = var.tfe_license
    tfe_hostname            = var.dns_record
    tfe_encryption_password = var.tfe_encryption_password
    tfe_image_tag           = var.tfe_image_tag
    certs_dir               = "/etc/terraform-enterprise/certs"
    data_dir                = "/opt/terraform-enterprise/data"
  })

  tags = { Name = var.name }
}

# --- Route53 Hosted Zone ---
data "aws_route53_zone" "server_zone" {
  name         = var.hosted_zone_name
  private_zone = false
}

# --- Route53 A Record pointing to EC2 public IP ---
resource "aws_route53_record" "server" {
  zone_id = data.aws_route53_zone.server_zone.zone_id
  name    = var.dns_record
  type    = "A"
  ttl     = 60

  records = [aws_instance.this.public_ip]
}

# ACME account private key (used to register with Let's Encrypt)
resource "tls_private_key" "acme_account" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# ACME registration (your Let's Encrypt account)
resource "acme_registration" "this" {
  account_key_pem = tls_private_key.acme_account.private_key_pem
  email_address   = "mohamed.abdelbaset@hashicorp.com"
}

# ACME certificate for your FQDN
resource "acme_certificate" "server" {
  account_key_pem = acme_registration.this.account_key_pem
  common_name     = var.dns_record

  # Default is 30 days – cert will only be renewed when it's close to expiring,
  # not on every apply. :contentReference[oaicite:1]{index=1}
  min_days_remaining = 30

  dns_challenge {
    provider = "route53"
    config = {
      AWS_HOSTED_ZONE_ID = data.aws_route53_zone.server_zone.zone_id
      AWS_REGION         = var.region
    }
  }
}

# Store cert and ket in SSM Parameter Store
resource "aws_ssm_parameter" "tls_cert" {
  name  = "/tls/server/cert"
  type  = "SecureString"
  value = acme_certificate.server.certificate_pem
}

resource "aws_ssm_parameter" "tls_key" {
  name  = "/tls/server/key"
  type  = "SecureString"
  value = acme_certificate.server.private_key_pem
}

# IAM Policy to allow EC2 instance to read TLS certs from SSM Parameter Store
resource "aws_iam_role_policy" "ssm_tls_access" {
  role = aws_iam_role.ssm.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters"
        ],
        Resource = [
          "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/tls/server/*"
        ]
      }
    ]
  })
}

data "aws_caller_identity" "current" {}
