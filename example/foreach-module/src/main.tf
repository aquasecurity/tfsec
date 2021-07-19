
variable "targets" {
  default={
    "a" = {
      name = "test"
    },
    "b" = {
      name = "test"
    }
  }
}


module "ohdear" {
    for_each = var.targets
    source = "../module/"
    name = each.value.name
} 
