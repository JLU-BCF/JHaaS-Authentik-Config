######################
# Deployment configuration
######################

variable "kubeconfig_path" {
  description = "Path to kubernetes configuration file to use"
}
variable "k8s_namespace" {
  description = "The kubernetes namespace to deploy authentik in"
}
variable "release_name" {
  description = "The release name for the helm deployment"
}

######################
# Authentik configuration
######################

variable "authentik_version" {
  description = "Authentik version, used as chart version and image tag"
}
variable "authentik_hostname" {
  description = "Hostname under which authentik will be deployed"
}
variable "authentik_secret" {
  description = "The authentik secret to sign cookies and do other stuff"
}
variable "authentik_token" {
  description = "API token injected as token for akadmin"
}
variable "authentik_password" {
  description = "Password injected as password for akadmin"
}
variable "authentik_email" {
  description = "Email address injected as email address for akadmin"
}

######################
# Database configuration
######################

variable "postgresql_enabled" {
  description = "Controls if the buildin postgres chart should be deployed"
}
variable "postgres_name" {
  description = "Database name"
}
variable "postgres_user" {
  description = "Database user"
}
variable "postgres_pass" {
  description = "Database password"
}

######################
# Ingress configuration
######################

variable "use_tls" {
  description = "Control if tls is used by ingress"
}
variable "ingress_use_tls_acme" {
  description = "Sets the kubernetes.io/tls-acme annotation for ingress"
}
variable "ingress_tls_secret_name" {
  description = "Sets the secret name for tls for ingress"
}
variable "ingress_cert_manager_issuer" {
  description = "Sets the cert-manager.io/cluster-issuer annotation for ingress"
}
