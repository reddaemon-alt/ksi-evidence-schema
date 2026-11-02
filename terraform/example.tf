# Example: emitting a KSI evidence record from Terraform state.
#
# This is illustrative. It uses the null provider so it plans anywhere with no
# cloud credentials. In a real deployment the data source would be the cloud
# provider's resource (an identity policy, an inventory export, etc), and the
# check block would assert the KSI condition against live state on every plan.
#
# The idea: evidence is a byproduct of the deployment, not a separate
# document someone writes after the fact. Every `terraform plan` re-validates
# the KSI and the rendered record is what gets shipped to the evidence store.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}

# Stand-in for an authentication policy resource. In practice this would be
# something like an IdP policy resource with an `allowed_factors` attribute.
variable "allowed_factors" {
  description = "Authenticators permitted by the in-scope authentication policy."
  type        = list(string)
  default     = ["fido2", "piv"]
}

variable "phishing_resistant_factors" {
  description = "Authenticators FedRAMP treats as phishing-resistant for KSI-IAM-APM."
  type        = list(string)
  default     = ["fido2", "piv", "passkey"]
}

locals {
  # True when every allowed factor is phishing-resistant.
  iam_apm_met = length(setsubtract(toset(var.allowed_factors), toset(var.phishing_resistant_factors))) == 0

  ksi_iam_apm_record = {
    ksi_id        = "KSI-IAM-APM"
    statement     = "Secure passwordless methods are used for user authentication and authorization when feasible, otherwise strong passwords with phishing-resistant MFA is used."
    class         = "B"
    evidence_type = "config_export"
    source = {
      system = "iac-state"
      query  = "terraform plan ; check.ksi_iam_apm"
    }
    collected_at = timestamp()
    result       = local.iam_apm_met
    rationale    = local.iam_apm_met ? "Allowed factors ${jsonencode(var.allowed_factors)} are all phishing-resistant." : "Allowed factors ${jsonencode(var.allowed_factors)} include at least one non phishing-resistant authenticator."
    owner        = "identity-engineering"
    related_800_53_controls = [
      "ac-2", "ac-3", "ia-2", "ia-2.1", "ia-2.2", "ia-2.6", "ia-2.8",
      "ia-5", "ia-5.1", "ia-5.2", "ia-5.6", "ia-5.8", "ia-6",
      "ia-8", "ia-8.2", "ia-8.4", "sc-23"
    ]
  }
}

# Terraform 1.5+ check block: surfaces a warning on every plan/apply when the
# KSI condition is not met, without blocking the run. Swap for a precondition
# if the KSI should be a hard gate.
check "ksi_iam_apm" {
  assert {
    condition     = local.iam_apm_met
    error_message = "KSI-IAM-APM not met: a non phishing-resistant authenticator is allowed."
  }
}

# Writes the record so a pipeline step can pick it up and run validate.py on it.
resource "null_resource" "ksi_iam_apm_evidence" {
  triggers = {
    record = jsonencode(local.ksi_iam_apm_record)
  }

  provisioner "local-exec" {
    command = "mkdir -p ../evidence && printf '%s' '${jsonencode(local.ksi_iam_apm_record)}' > ../evidence/ksi-iam-apm.json"
  }
}

output "ksi_iam_apm_record" {
  value = local.ksi_iam_apm_record
}
