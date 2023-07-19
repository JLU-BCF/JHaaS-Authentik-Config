# Configure the terraform provider
variable "authentik_token" {
  description = "Authentic token that will be used for API calls."
  default     = "tokentokentokentokentokentokentokentokentokentoken"
}

# Configure authentik Accessibility
variable "authentik_domain" {
  description = "Domain where Authentik is accessible."
  default     = "localhost"
}

variable "authentik_port" {
  description = "Port where authentik is accessible. Set null to omit a port and use defaults (80/443)."
  default     = 9000
}

variable "authentik_ssl" {
  description = "Control use of https (true) oder http (null)."
  default     = null
}

variable "authentik_path" {
  description = "Path where Authentik is accessible."
  default     = ""
}

# Configure JHaaS Accessibility
variable "jhaas_domain" {
  description = "The domain where JHaaS is accessible."
  default     = "localhost"
}

variable "jhaas_port" {
  description = "Port where JHaaS is accessible. Set null to omit a port and use defaults (80/443)."
  default     = 3000
}

variable "jhaas_ssl" {
  description = "Control use of https (true) oder http (null)."
  default     = null
}

variable "jhaas_path" {
  description = "Path where JHaaS is accessible."
  default     = ""
}

# Configure the OAuth Provider for JHaaS Portal
variable "authentik_jhaas_client_id" {
  description = "The client_id for the default jhaas provider."
  default     = "jhaas-portal"
}

variable "authentik_jhaas_client_secret" {
  description = "Secret to be set for the jhaas provider."
  default     = "mysupersecretclientsecretmysupersecretclientsecret"
}

variable "authentik_provider_redirect_uri" {
  description = "Allowed redirection URLs for jhaas provider."
  default     = null
}

# Configure Flows
variable "authentik_jhaas_login_flow" {
  description = "URL for the JHaaS authentication flow."
  default     = "/if/flow/auth"
}

variable "authentik_flow_background" {
  description = "Default Background applied to all flows."
  default     = "/static/dist/assets/images/flow_background.jpg"
}

variable "authentik_tos_url" {
  description = "URL linked in TOS text"
  default     = null
}

variable "authentik_jhaas_login_redirect" {
  description = "URL for the JHaaS login redirect."
  default     = null
}

variable "authentik_jhaas_verify_redirect" {
  description = "URL for the JHaaS verify redirect."
  default     = null
}

variable "authentik_jhaas_launch_url" {
  description = "URL for the JHaaS launcher redirect."
  default     = null
}

# Configure Application
variable "authentik_jhaas_slogan" {
  description = "Slogan displayed for the JHaaS launcher."
  default     = "Create your personal Jupyter Hub instance on the go"
}

variable "authentik_branding_title" {
  description = "Title displayed by the web application."
  default     = "JHaaS"
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

# Configure Mails
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
