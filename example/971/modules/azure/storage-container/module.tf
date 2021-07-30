resource "azurerm_storage_container" "containers" {
    name                  = var.name
    storage_account_name  = var.storage_account_name
}

variable "storage_account_name" {

}

variable "name" {
    default = ""
}