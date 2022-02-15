module "storage" {
    source     = "../../modules/azure/storage-account"
    name       = "mystorageaccount"
    containers = { "mycontainer" = {} }
}
