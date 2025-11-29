# GCP Network Security Configuration
# VPC, Firewall Rules, and Network Security

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

# Variables
variable "project_id" {
  type        = string
  description = "GCP Project ID"
}

variable "environment" {
  type        = string
  description = "Environment name"
  default     = "production"
}

variable "region" {
  type        = string
  description = "GCP Region"
  default     = "us-central1"
}

variable "vpc_cidr" {
  type        = string
  description = "VPC CIDR range"
  default     = "10.0.0.0/16"
}

variable "enable_flow_logs" {
  type        = bool
  description = "Enable VPC Flow Logs"
  default     = true
}

variable "enable_private_google_access" {
  type        = bool
  description = "Enable Private Google Access"
  default     = true
}

# VPC Network
resource "google_compute_network" "main" {
  project                         = var.project_id
  name                            = "${var.environment}-vpc"
  auto_create_subnetworks         = false
  routing_mode                    = "GLOBAL"
  delete_default_routes_on_create = true
}

# Public Subnet
resource "google_compute_subnetwork" "public" {
  project                  = var.project_id
  name                     = "${var.environment}-public-subnet"
  ip_cidr_range            = cidrsubnet(var.vpc_cidr, 8, 0)
  region                   = var.region
  network                  = google_compute_network.main.id
  private_ip_google_access = var.enable_private_google_access

  dynamic "log_config" {
    for_each = var.enable_flow_logs ? [1] : []
    content {
      aggregation_interval = "INTERVAL_5_SEC"
      flow_sampling        = 0.5
      metadata             = "INCLUDE_ALL_METADATA"
    }
  }
}

# Private Subnet
resource "google_compute_subnetwork" "private" {
  project                  = var.project_id
  name                     = "${var.environment}-private-subnet"
  ip_cidr_range            = cidrsubnet(var.vpc_cidr, 8, 1)
  region                   = var.region
  network                  = google_compute_network.main.id
  private_ip_google_access = true

  dynamic "log_config" {
    for_each = var.enable_flow_logs ? [1] : []
    content {
      aggregation_interval = "INTERVAL_5_SEC"
      flow_sampling        = 0.5
      metadata             = "INCLUDE_ALL_METADATA"
    }
  }
}

# Database Subnet
resource "google_compute_subnetwork" "database" {
  project                  = var.project_id
  name                     = "${var.environment}-database-subnet"
  ip_cidr_range            = cidrsubnet(var.vpc_cidr, 8, 2)
  region                   = var.region
  network                  = google_compute_network.main.id
  private_ip_google_access = true

  dynamic "log_config" {
    for_each = var.enable_flow_logs ? [1] : []
    content {
      aggregation_interval = "INTERVAL_5_SEC"
      flow_sampling        = 1.0
      metadata             = "INCLUDE_ALL_METADATA"
    }
  }
}

# Cloud Router for NAT
resource "google_compute_router" "main" {
  project = var.project_id
  name    = "${var.environment}-router"
  region  = var.region
  network = google_compute_network.main.id

  bgp {
    asn = 64514
  }
}

# Cloud NAT
resource "google_compute_router_nat" "main" {
  project                            = var.project_id
  name                               = "${var.environment}-nat"
  router                             = google_compute_router.main.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Default Route to Internet (via NAT)
resource "google_compute_route" "default" {
  project          = var.project_id
  name             = "${var.environment}-default-route"
  dest_range       = "0.0.0.0/0"
  network          = google_compute_network.main.name
  next_hop_gateway = "default-internet-gateway"
  priority         = 1000
}

# Firewall Rule - Deny All Ingress (Default)
resource "google_compute_firewall" "deny_all_ingress" {
  project     = var.project_id
  name        = "${var.environment}-deny-all-ingress"
  network     = google_compute_network.main.name
  priority    = 65534
  direction   = "INGRESS"
  description = "Deny all ingress traffic by default"

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Firewall Rule - Allow Internal
resource "google_compute_firewall" "allow_internal" {
  project     = var.project_id
  name        = "${var.environment}-allow-internal"
  network     = google_compute_network.main.name
  priority    = 1000
  direction   = "INGRESS"
  description = "Allow internal VPC traffic"

  allow {
    protocol = "tcp"
  }

  allow {
    protocol = "udp"
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = [var.vpc_cidr]
}

# Firewall Rule - Allow HTTPS from Load Balancer
resource "google_compute_firewall" "allow_https_lb" {
  project     = var.project_id
  name        = "${var.environment}-allow-https-lb"
  network     = google_compute_network.main.name
  priority    = 1000
  direction   = "INGRESS"
  description = "Allow HTTPS from Google Load Balancer"

  allow {
    protocol = "tcp"
    ports    = ["443", "8443"]
  }

  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  target_tags   = ["https-server"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Firewall Rule - Allow Health Checks
resource "google_compute_firewall" "allow_health_checks" {
  project     = var.project_id
  name        = "${var.environment}-allow-health-checks"
  network     = google_compute_network.main.name
  priority    = 1000
  direction   = "INGRESS"
  description = "Allow Google health check probes"

  allow {
    protocol = "tcp"
  }

  source_ranges = ["35.191.0.0/16", "130.211.0.0/22", "209.85.152.0/22", "209.85.204.0/22"]
  target_tags   = ["health-check"]
}

# Firewall Rule - Allow IAP for SSH
resource "google_compute_firewall" "allow_iap_ssh" {
  project     = var.project_id
  name        = "${var.environment}-allow-iap-ssh"
  network     = google_compute_network.main.name
  priority    = 1000
  direction   = "INGRESS"
  description = "Allow SSH via Identity-Aware Proxy"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["iap-ssh"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Firewall Rule - Deny Egress to Internet (except allowed)
resource "google_compute_firewall" "deny_egress_internet" {
  project     = var.project_id
  name        = "${var.environment}-deny-egress-internet"
  network     = google_compute_network.main.name
  priority    = 65534
  direction   = "EGRESS"
  description = "Deny egress to internet for restricted workloads"

  deny {
    protocol = "all"
  }

  destination_ranges = ["0.0.0.0/0"]
  target_tags        = ["restricted-egress"]
}

# Private Service Connection for Cloud SQL
resource "google_compute_global_address" "private_ip_range" {
  project       = var.project_id
  name          = "${var.environment}-private-ip-range"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.main.id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.main.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_range.name]
}

# VPC Service Controls Perimeter (requires Access Context Manager)
# resource "google_access_context_manager_service_perimeter" "security" {
#   parent = "accessPolicies/${var.access_policy_id}"
#   name   = "accessPolicies/${var.access_policy_id}/servicePerimeters/${var.environment}_perimeter"
#   title  = "${var.environment} Security Perimeter"
#   status {
#     restricted_services = [
#       "storage.googleapis.com",
#       "bigquery.googleapis.com"
#     ]
#   }
# }

# Outputs
output "vpc_id" {
  description = "VPC network ID"
  value       = google_compute_network.main.id
}

output "vpc_name" {
  description = "VPC network name"
  value       = google_compute_network.main.name
}

output "public_subnet_id" {
  description = "Public subnet ID"
  value       = google_compute_subnetwork.public.id
}

output "private_subnet_id" {
  description = "Private subnet ID"
  value       = google_compute_subnetwork.private.id
}

output "database_subnet_id" {
  description = "Database subnet ID"
  value       = google_compute_subnetwork.database.id
}

output "router_name" {
  description = "Cloud Router name"
  value       = google_compute_router.main.name
}

output "nat_name" {
  description = "Cloud NAT name"
  value       = google_compute_router_nat.main.name
}
