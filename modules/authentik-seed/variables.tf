variable "authentik_url" {
}

variable "authentik_token" {
}

variable "authentik_jhaas_client_id" {

}

variable "authentik_jhaas_client_secret" {

}

variable "authentik_provider_redirect_uri" {
  # e.g. https?://jhaas-test\.gi\.denbi\.de/.*
}

variable "authentik_flow_background" {
  description = "Default Background applied to all flows"
  default = "/static/dist/assets/images/flow_background.jpg"
}

variable "authentik_tos_url" {
  description = "URL linked in TOS text"
}

variable "authentik_jhaas_login_flow" {
  description = "URL for the JHaaS authentication flow"
  default = "/if/flow/auth"
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

variable "authentik_jhaas_launch_url" {
  description = "URL for the JHaaS launcher redirect"
  # e.g. https://jhaas-test.gi.denbi.de/api/auth/oidc/login
}

variable "authentik_jhaas_slogan" {
  description = "Slogan displayed for the JHaaS launcher"
  default = "Create your personal Jupyter Hub instance on the go"
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

variable "authentik_branding_title" {
  default = "JHaaS"
}

variable "authentik_branding_favicon" {
  default = "/static/dist/assets/icons/icon.png"
}

variable "authentik_branding_logo" {
  default = "/static/dist/assets/icons/icon_left_brand.svg"
}

variable "authentik_branding_publisher" {
  default = ""
}

variable "authentik_domain" {
}
