variable "region" {
  description = "AWS region to deploy resources in"
  type        = string
}

variable "name" {
  description = "Name for the EC2 instance"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
}

variable "hosted_zone_name" {
  description = "Route53 Hosted Zone Name"
  type        = string
}

variable "dns_record" {
  description = "DNS record"
  type        = string
}

variable "tfe_license" {
  description = "Terraform Enterprise License"
  type        = string
  sensitive   = true
}

variable "tfe_admin_password" {
  description = "Password used for TFE admin user."
  type        = string
  sensitive   = true
}

variable "tfe_encryption_password" {
  description = "Password used to encrypt TFE data."
  type        = string
  sensitive   = true
}

variable "tfe_image_tag" {
  type        = string
  description = "TFE image version to install"
}

variable "rds_password" {
  type        = string
  description = "The password for the RDS instance"
  sensitive   = true
}
