provider "helm" {
  kubernetes {
    config_path = var.kubeconfig_path
  }
}

provider "kubernetes" {
  config_path = var.kubeconfig_path
}

provider "kubectl" {
  config_path = var.kubeconfig_path
}

# install cert manager and create an issuer
# module "cert_manager" {
#   source        = "terraform-iaac/cert-manager/kubernetes"
#   version = "2.5.1"

#   cluster_issuer_email                   = var.authentik_email
#   cluster_issuer_name                    = "cert-manager"
#   cluster_issuer_private_key_secret_name = "cert-manager-private-key"
# }

# deploy nginx ingress controller
module "nginx-controller" {
  source  = "terraform-iaac/nginx-controller/helm"

  create_namespace = true
  controller_kind = "Deployment"
  namespace = "nginx-ingress"
  define_nodePorts = false

  additional_set = []
}

# Create the kubernetes namespace explicitly
# to deploy authentik in
resource "kubernetes_namespace" "authentik" {
  metadata {
    name = var.k8s_namespace
  }
}

# resource "helm_release" "authentik" {
#   depends_on = [ kubernetes_namespace.authentik ]

#   name              = "authentik"
#   chart             = "authentik"
#   repository        = "https://charts.goauthentik.io/"
#   version           = var.authentik_version
#   namespace         = var.k8s_namespace
#   wait              = true
#   wait_for_jobs     = true
#   create_namespace  = false

#   values = [
#     "${file("${path.module}/values.yaml")}",
#     "${file("data/authentik-override.values.yaml")}"
#   ]

#   ######################
#   # Set basic configuration
#   ######################

#   set {
#     name = "image.tag"
#     value = var.authentik_version
#   }

#   set {
#     name = "authentik.secret_key"
#     value = var.authentik_secret
#   }

#   ######################
#   # Set environment vars for automated setup
#   ######################

#   set {
#     name = "env.AUTHENTIK_BOOTSTRAP_PASSWORD"
#     value = var.authentik_password
#   }

#   set {
#     name = "env.AUTHENTIK_BOOTSTRAP_TOKEN"
#     value = var.authentik_token
#   }

#   set {
#     name = "env.AUTHENTIK_BOOTSTRAP_EMAIL"
#     value = var.authentik_email
#   }

#   ######################
#   # overwrite psql config, if buildin psql is enabled
#   ######################

#   set {
#     name = var.postgresql_enabled ? "authentik.postgresql.name" : ".discard"
#     value = var.postgres_name
#   }

#   set {
#     name = var.postgresql_enabled ? "postgresql.postgresqlDatabase" : ".discard"
#     value = var.postgres_name
#   }

#   set {
#     name = var.postgresql_enabled ? "authentik.postgresql.user" : ".discard"
#     value = var.postgres_user
#   }

#   set {
#     name = var.postgresql_enabled ? "postgresql.postgresqlUsername" : ".discard"
#     value = var.postgres_user
#   }

#   set {
#     name = var.postgresql_enabled ? "authentik.postgresql.password" : ".discard"
#     value = var.postgres_pass
#   }

#   set {
#     name = var.postgresql_enabled ? "postgresql.postgresqlPassword" : ".discard"
#     value = var.postgres_pass
#   }

#   ######################
#   # override first ingress host
#   ######################

#   set {
#     name = "ingress.annotations.kubernetes\\.io/tls-acme"
#     value = var.ingress_use_tls_acme
#   }

#   set {
#     name = "ingress.annotations.cert-manager\\.io/cluster-issuer"
#     value = var.ingress_cert_manager_issuer
#   }

#   set {
#     name = "ingress.hosts[0].host"
#     value = var.authentik_hostname
#   }

#   set {
#     name = "ingress.hosts[0].host"
#     value = var.authentik_hostname
#   }

#   # set_list {
#   #   name = "ingress.hosts"
#   #   value = [{
#   #     host = var.authentik_hostname,
#   #     paths = [{
#   #       path = "/",
#   #       pathType = "Prefix"
#   #     }]
#   #   }]
#   # }

#   # set_list {
#   #   name = var.use_tls ? "ingress.tls" : ".discard"
#   #   value = [{
#   #     hosts = [ var.authentik_hostname ],
#   #     secretName = var.ingress_tls_secret_name
#   #   }]
#   # }

# }
