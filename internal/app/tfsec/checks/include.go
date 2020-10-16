package checks

// ensure all init() funcs are called
import (
    _ "github.com/tfsec/tfsec/internal/app/tfsec/checks/aws"
    _ "github.com/tfsec/tfsec/internal/app/tfsec/checks/azure"
    _ "github.com/tfsec/tfsec/internal/app/tfsec/checks/general"
    _ "github.com/tfsec/tfsec/internal/app/tfsec/checks/google"
)
