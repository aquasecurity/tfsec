resource "azurerm_storage_account" "storage_accounts" {
    name            = var.name
    min_tls_version = "TLS1_2"
}

resource "azurerm_storage_account_queue_properties" "storage_accounts" {
    storage_account_id = azurerm_storage_account.storage_accounts.id

    logging {
        read                  = true
        write                 = true
        delete                = true
        version               = "1.0"
        retention_policy_days = 7
    }
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

