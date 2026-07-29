resource "azurerm_storage_account" "storage_accounts" {
    name            = var.name
    min_tls_version = "TLS1_2"

    queue_properties {
        logging {
            delete                = true
            read                  = true
            write                 = true
            version               = "1.0"
            retention_policy_days = 10
        }
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

