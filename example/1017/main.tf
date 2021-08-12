module "label8d" {
  source = "../../"

  enabled     = true
  namespace   = "eg"
  environment = "demo"
  name        = "blue"
  attributes  = ["cluster"]
  delimiter   = "-"

  tags = {
    "kubernetes.io/cluster/" = "shared"
  }
}

module "label8d_context" {
  source = "../../"

  context = module.label8d.context
}

output "label8d_context_id" {
  value = module.label8d_context.id
}

output "label8d_context_context" {
  value = module.label8d_context.context
}

output "label8d_context_tags" {
  value = module.label8d_context.tags
}

output "label8d_id" {
  value = module.label8d.id
}

output "label8d_context" {
  value = module.label8d.context
}

output "label8d_tags" {
  value = module.label8d.tags
}