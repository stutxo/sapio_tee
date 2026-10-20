# Optional Route53 zone and stable deployment record for the project domain.
#
# The domain is registered outside AWS (Namecheap). Create the hosted zone here
# once, then set the four Route53 name servers as the domain's custom DNS at the
# registrar. Later deployments should set manage_dns_zone = false and reuse the
# existing zone via dns_zone_id.
#
# The A record points at the deployment's stable Elastic IP. It does not add TLS
# or request authentication: the enclave API and signer remain plaintext and
# unauthenticated. Keep their security-group ingress closed to the Internet
# unless a reviewed front proxy provides authentication, rate limiting and TLS.

variable "domain_name" {
  description = "Apex domain registered at the external registrar."
  type        = string
  default     = "sapio.sh"

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", var.domain_name))
    error_message = "Use a lowercase DNS name such as sapio.sh."
  }
}

variable "manage_dns_zone" {
  description = "Create the Route53 hosted zone. Set true only for the first apply/account that owns the zone; otherwise reuse dns_zone_id."
  type        = bool
  default     = false
}

variable "dns_zone_id" {
  description = "Existing Route53 hosted zone ID for domain_name. Ignored when manage_dns_zone is true."
  type        = string
  default     = ""

  validation {
    condition     = var.dns_zone_id == "" || can(regex("^Z[0-9A-Z]+$", var.dns_zone_id))
    error_message = "Use a Route53 hosted zone ID such as Z0123456789ABCDEFGHIJ, or leave empty."
  }
}

variable "dns_record_name" {
  description = "Relative record name for the deployment, e.g. tee -> tee.sapio.sh."
  type        = string
  default     = "tee"

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.dns_record_name))
    error_message = "Use a single lowercase DNS label such as tee."
  }
}

locals {
  dns_zone_id        = var.manage_dns_zone ? aws_route53_zone.sapio[0].zone_id : var.dns_zone_id
  dns_record_enabled = local.dns_zone_id != ""
}

resource "aws_route53_zone" "sapio" {
  count = var.manage_dns_zone ? 1 : 0

  name    = var.domain_name
  comment = "Sapio TEE deployment domain; retain and delegate from the registrar"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_route53_record" "deployment" {
  count = local.dns_record_enabled ? 1 : 0

  zone_id = local.dns_zone_id
  name    = "${var.dns_record_name}.${var.domain_name}"
  type    = "A"
  ttl     = 60
  records = [aws_eip.parent.public_ip]
}

output "dns_zone_id" {
  description = "Route53 hosted zone ID used for the deployment record."
  value       = local.dns_zone_id
}

output "dns_name_servers" {
  description = "Route53 name servers to set as custom DNS at the registrar when manage_dns_zone is true."
  value       = var.manage_dns_zone ? aws_route53_zone.sapio[0].name_servers : []
}

output "dns_record_fqdn" {
  description = "Fully qualified A record for the stable Elastic IP, or empty when DNS is not configured."
  value       = local.dns_record_enabled ? aws_route53_record.deployment[0].fqdn : ""
}
