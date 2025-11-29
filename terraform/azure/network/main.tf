# Azure Network Security Configuration
# VNet, NSG, Azure Firewall, and DDoS Protection

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

# Variables
variable "environment" {
  type        = string
  description = "Environment name"
  default     = "production"
}

variable "location" {
  type        = string
  description = "Azure region"
  default     = "eastus"
}

variable "resource_group_name" {
  type        = string
  description = "Resource group name"
}

variable "vnet_address_space" {
  type        = list(string)
  description = "VNet address space"
  default     = ["10.0.0.0/16"]
}

variable "enable_ddos_protection" {
  type        = bool
  description = "Enable DDoS Protection Plan"
  default     = true
}

variable "enable_azure_firewall" {
  type        = bool
  description = "Enable Azure Firewall"
  default     = true
}

# Virtual Network
resource "azurerm_virtual_network" "main" {
  name                = "${var.environment}-vnet"
  location            = var.location
  resource_group_name = var.resource_group_name
  address_space       = var.vnet_address_space

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Subnets
resource "azurerm_subnet" "public" {
  name                 = "${var.environment}-public-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [cidrsubnet(var.vnet_address_space[0], 8, 0)]
}

resource "azurerm_subnet" "private" {
  name                 = "${var.environment}-private-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [cidrsubnet(var.vnet_address_space[0], 8, 1)]

  service_endpoints = [
    "Microsoft.Storage",
    "Microsoft.Sql",
    "Microsoft.KeyVault"
  ]
}

resource "azurerm_subnet" "database" {
  name                 = "${var.environment}-database-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [cidrsubnet(var.vnet_address_space[0], 8, 2)]

  delegation {
    name = "fs"
    service_delegation {
      name = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action"
      ]
    }
  }

  service_endpoints = ["Microsoft.Storage"]
}

resource "azurerm_subnet" "firewall" {
  count                = var.enable_azure_firewall ? 1 : 0
  name                 = "AzureFirewallSubnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [cidrsubnet(var.vnet_address_space[0], 8, 255)]
}

# Network Security Group - Public Subnet
resource "azurerm_network_security_group" "public" {
  name                = "${var.environment}-public-nsg"
  location            = var.location
  resource_group_name = var.resource_group_name

  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowHTTP"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Network Security Group - Private Subnet
resource "azurerm_network_security_group" "private" {
  name                = "${var.environment}-private-nsg"
  location            = var.location
  resource_group_name = var.resource_group_name

  security_rule {
    name                       = "AllowVNetInbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "VirtualNetwork"
  }

  security_rule {
    name                       = "DenyInternetInbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Network Security Group - Database Subnet
resource "azurerm_network_security_group" "database" {
  name                = "${var.environment}-database-nsg"
  location            = var.location
  resource_group_name = var.resource_group_name

  security_rule {
    name                       = "AllowPostgreSQL"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5432"
    source_address_prefix      = var.vnet_address_space[0]
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowMySQL"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3306"
    source_address_prefix      = var.vnet_address_space[0]
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# NSG Associations
resource "azurerm_subnet_network_security_group_association" "public" {
  subnet_id                 = azurerm_subnet.public.id
  network_security_group_id = azurerm_network_security_group.public.id
}

resource "azurerm_subnet_network_security_group_association" "private" {
  subnet_id                 = azurerm_subnet.private.id
  network_security_group_id = azurerm_network_security_group.private.id
}

resource "azurerm_subnet_network_security_group_association" "database" {
  subnet_id                 = azurerm_subnet.database.id
  network_security_group_id = azurerm_network_security_group.database.id
}

# DDoS Protection Plan
resource "azurerm_network_ddos_protection_plan" "main" {
  count               = var.enable_ddos_protection ? 1 : 0
  name                = "${var.environment}-ddos-plan"
  location            = var.location
  resource_group_name = var.resource_group_name

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Azure Firewall
resource "azurerm_public_ip" "firewall" {
  count               = var.enable_azure_firewall ? 1 : 0
  name                = "${var.environment}-firewall-pip"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "azurerm_firewall_policy" "main" {
  count               = var.enable_azure_firewall ? 1 : 0
  name                = "${var.environment}-firewall-policy"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "Premium"

  threat_intelligence_mode = "Deny"

  dns {
    proxy_enabled = true
  }

  intrusion_detection {
    mode = "Deny"
  }

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "azurerm_firewall" "main" {
  count               = var.enable_azure_firewall ? 1 : 0
  name                = "${var.environment}-firewall"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku_name            = "AZFW_VNet"
  sku_tier            = "Premium"
  firewall_policy_id  = azurerm_firewall_policy.main[0].id

  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.firewall[0].id
    public_ip_address_id = azurerm_public_ip.firewall[0].id
  }

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Firewall Application Rule Collection
resource "azurerm_firewall_policy_rule_collection_group" "main" {
  count              = var.enable_azure_firewall ? 1 : 0
  name               = "${var.environment}-rcg"
  firewall_policy_id = azurerm_firewall_policy.main[0].id
  priority           = 500

  application_rule_collection {
    name     = "AllowedWebCategories"
    priority = 100
    action   = "Allow"

    rule {
      name = "AllowMicrosoft"
      protocols {
        type = "Https"
        port = 443
      }
      source_addresses  = [var.vnet_address_space[0]]
      destination_fqdns = ["*.microsoft.com", "*.azure.com", "*.windows.net"]
    }
  }

  network_rule_collection {
    name     = "AllowDNS"
    priority = 200
    action   = "Allow"

    rule {
      name                  = "DNS"
      protocols             = ["UDP", "TCP"]
      source_addresses      = [var.vnet_address_space[0]]
      destination_addresses = ["168.63.129.16"]
      destination_ports     = ["53"]
    }
  }
}

# Network Watcher Flow Logs
resource "azurerm_network_watcher" "main" {
  name                = "${var.environment}-network-watcher"
  location            = var.location
  resource_group_name = var.resource_group_name

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Storage Account for Flow Logs
resource "azurerm_storage_account" "flowlogs" {
  name                     = "${var.environment}flowlogs"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# NSG Flow Logs
resource "azurerm_network_watcher_flow_log" "public" {
  network_watcher_name = azurerm_network_watcher.main.name
  resource_group_name  = var.resource_group_name
  name                 = "${var.environment}-public-flowlog"

  network_security_group_id = azurerm_network_security_group.public.id
  storage_account_id        = azurerm_storage_account.flowlogs.id
  enabled                   = true
  version                   = 2

  retention_policy {
    enabled = true
    days    = 90
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.flowlogs.workspace_id
    workspace_region      = var.location
    workspace_resource_id = azurerm_log_analytics_workspace.flowlogs.id
    interval_in_minutes   = 10
  }
}

# Log Analytics Workspace for Flow Logs
resource "azurerm_log_analytics_workspace" "flowlogs" {
  name                = "${var.environment}-flowlogs-workspace"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Outputs
output "vnet_id" {
  description = "Virtual Network ID"
  value       = azurerm_virtual_network.main.id
}

output "vnet_name" {
  description = "Virtual Network name"
  value       = azurerm_virtual_network.main.name
}

output "public_subnet_id" {
  description = "Public subnet ID"
  value       = azurerm_subnet.public.id
}

output "private_subnet_id" {
  description = "Private subnet ID"
  value       = azurerm_subnet.private.id
}

output "database_subnet_id" {
  description = "Database subnet ID"
  value       = azurerm_subnet.database.id
}

output "firewall_private_ip" {
  description = "Azure Firewall private IP"
  value       = var.enable_azure_firewall ? azurerm_firewall.main[0].ip_configuration[0].private_ip_address : null
}
