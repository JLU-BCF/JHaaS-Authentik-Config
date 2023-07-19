locals {
  authentik_proto_string = var.authentik_ssl != null ? "https" : "http"
  authentik_port_string  = var.authentik_port != null ? ":${var.authentik_port}" : ""
  authentik_url          = "${local.authentik_proto_string}://${var.authentik_domain}${local.authentik_port_string}${var.authentik_path}"

  jhaas_proto_string = var.jhaas_ssl != null ? "https" : "http"
  jhaas_port_string  = var.jhaas_port != null ? ":${var.jhaas_port}" : ""
  jhaas_url          = "${local.jhaas_proto_string}://${var.jhaas_domain}${local.jhaas_port_string}${var.jhaas_path}"

  authentik_provider_redirect_uri = var.authentik_provider_redirect_uri != null ? var.authentik_provider_redirect_uri : "${local.jhaas_url}/api/auth/oidc/cb"

  authentik_tos_url               = var.authentik_tos_url != null ? var.authentik_tos_url : "${local.jhaas_url}/tos"
  authentik_jhaas_login_redirect  = var.authentik_jhaas_login_redirect != null ? var.authentik_jhaas_login_redirect : "${local.jhaas_url}/api/auth/oidc/cb"
  authentik_jhaas_verify_redirect = var.authentik_jhaas_verify_redirect != null ? var.authentik_jhaas_verify_redirect : "${local.jhaas_url}/verify"
  authentik_jhaas_launch_url      = var.authentik_jhaas_launch_url != null ? var.authentik_jhaas_launch_url : "${local.jhaas_url}/api/auth/oidc/login"
}
