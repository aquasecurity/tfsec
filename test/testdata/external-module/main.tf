
module "enforce_mfa" {
  source  = "terraform-module/enforce-mfa/aws"
  version = "0.12.0"

  policy_name                     = "managed-mfa-enforce"
  manage_own_signing_certificates = true
  manage_own_ssh_public_keys      = true
  manage_own_git_credentials      = true
}

