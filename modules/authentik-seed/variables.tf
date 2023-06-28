variable "authentik_flow_background" {
  description = "Default Background applied to all flows"
}

variable "authentik_tos_url" {
  description = "URL linked in TOS text"
}

variable "authentik_jhaas_login_flow" {
  description = "URL for the JHaaS authentication flow"
  # e.g. https://auth.jhaas.gi.denbi.de/if/flow/jhaas-authentication
}

variable "authentik_jhaas_login_redirect" {
  description = "URL for the JHaaS login redirect"
  # e.g. https://jhaas-test.gi.denbi.de/api/auth/oidc/cb
}

variable "authentik_jhaas_verify_redirect" {
  description = "URL for the JHaaS verify redirect"
  # e.g. https://jhaas-test.gi.denbi.de/verify
}

variable "authentik_email_subject_enrollment" {
  default = "Verify you Email address for JHaaS"
}

variable "authentik_email_template_enrollment" {
  default = "email/account_confirmation.html"
}

variable "authentik_email_subject_recovery" {
  default = "Reset your password for JHaaS"
}

variable "authentik_email_template_recovery" {
  default = "email/password_reset.html"
}
