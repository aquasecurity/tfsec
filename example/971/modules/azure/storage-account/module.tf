resource "azurerm_storage_account" "storage_accounts" {
    name = var.name
    
}

module "storage_container" {
    for_each = var.containers
    source   = "./../storage-container"
    storage_account_name = azurerm_storage_account.storage_accounts.name
}


variable "name" {

}

variable "containers" {

}

