variable "acme_server_url" {
  description = "acme server url to use"
  type        = string
}

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

variable "email" {
  description = "email used in acme cert and tfe admin user"
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

variable "certs_dir" {
  type        = string
  description = "Host directory where TLS certs are written and mounted into the TFE container"
  default     = "/etc/terraform-enterprise/certs"
}

variable "data_dir" {
  type        = string
  description = "Host directory for TFE persistent data (disk operational mode)"
  default     = "/opt/terraform-enterprise/data"
}
