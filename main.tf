provider "random" {}

# Create random secret key for authentik
resource "random_password" "authentik_secret" {
  length           = 50
  special          = false
}

# Create random api token for authentik akadmin
resource "random_password" "authentik_token" {
  length           = 60
  special          = false
}

# Create random password for authentik akadmin
resource "random_password" "authentik_password" {
  length           = 20
  special          = false
}

# Create random user for postgres DB
resource "random_pet" "db_user" {
  # length is in words
  length = 1
}

# Create random password for postgres DB
resource "random_password" "db_pass" {
  length           = 32
  special          = false
}

module "authentik-deploy" {
  source = "./modules/authentik-deploy"

  depends_on = [
    random_password.authentik_secret,
    random_password.authentik_token,
    random_password.authentik_password,
    random_pet.db_user,
    random_password.db_pass
  ]

  kubeconfig_path = var.kubeconfig_path
  k8s_namespace = var.k8s_namespace
  release_name = var.release_name

  authentik_version = var.authentik_version
  authentik_hostname = var.authentik_hostname
  authentik_secret = random_password.authentik_secret.result
  authentik_token = random_password.authentik_token.result
  authentik_password = random_password.authentik_password.result
  authentik_email = var.authentik_email

  postgresql_enabled = var.postgresql_enabled
  postgres_name = "authentik"
  postgres_user = random_pet.db_user.id
  postgres_pass = random_password.db_pass.result

  use_tls = var.use_tls
  ingress_use_tls_acme = var.ingress_use_tls_acme
  ingress_tls_secret_name = var.ingress_tls_secret_name
  ingress_cert_manager_issuer = var.ingress_cert_manager_issuer

}

module "authentik-seed" {
  source = "./modules/authentik-seed"

  depends_on = [
    module.authentik-deploy
  ]
}
