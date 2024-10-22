#
########################
#
# Add Groups
#
########################
#

# Group to identify the admins
resource "authentik_group" "admins" {
  name         = "admins"
  is_superuser = true
}

# Group to identify the government
resource "authentik_group" "portal_admins" {
  name = "portal-admins"
}

# Group to identify leaders
resource "authentik_group" "portal_leaders" {
  name = "portal-leaders"
}

# Group attached to users validated with trusted Source (e.g. LDAP)
resource "authentik_group" "auth_trusted" {
  name = "auth-trusted"
}

# Group attached to self registered users
resource "authentik_group" "auth_untrusted" {
  name = "auth-untrusted"
}

# Group to organize jupyterhubs
resource "authentik_group" "jupyterhubs" {
  name = "jupyterhubs"
}

#
########################
#
# Add Mappings
#
########################
#

# Map email attributes
resource "authentik_scope_mapping" "email" {
  name        = "jhaas-email"
  scope_name  = "email"
  description = "Map Email address"
  expression  = <<-SCOPE_EMAIL
      return {
          "email": request.user.email,
          "email_verified": True
      }
  SCOPE_EMAIL
}

# Map openid attributes
resource "authentik_scope_mapping" "openid" {
  name        = "jhaas-openid"
  scope_name  = "openid"
  description = "Map openid"
  expression  = <<-SCOPE_OPENID
      return {}
  SCOPE_OPENID
}

# Map profile attributes
resource "authentik_scope_mapping" "profile" {
  name        = "jhaas-profile"
  scope_name  = "profile"
  description = "Map profile"
  expression  = <<-SCOPE_PROFILE
      return {
          "name": request.user.name,
          "given_name": request.user.attributes.get("given_name", request.user.name),
          "family_name": request.user.attributes.get("family_name", request.user.name),
          "preferred_username": request.user.email,
          "nickname": request.user.attributes.get("given_name", request.user.name),
          "groups": [group.name for group in request.user.ak_groups.all()],
          "external_id": str(request.user.uuid),
      }
  SCOPE_PROFILE
}

# Map user attributes
resource "authentik_scope_mapping" "user_attributes" {
  name        = "jhaas-user-attributes"
  scope_name  = "user-attributes"
  description = "Map user attributes into OIDC response"
  expression  = <<-USER_ATTRIBUTES
      return request.user.attributes
  USER_ATTRIBUTES
}

#
########################
#
# Add Certificate Key Pair
#
########################
#

# Create a private RSA key to use for self signed authentik certificate
resource "tls_private_key" "authentik_self_signed" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# Create a RSA public key to use for self signed authentik certificate
resource "tls_self_signed_cert" "authentik_self_signed" {
  private_key_pem = tls_private_key.authentik_self_signed.private_key_pem

  subject {
    common_name = var.authentik_domain
  }

  dns_names = [var.authentik_domain]

  # 1 year
  validity_period_hours = 8760

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

# Create a certificate key pair from the self signed authentik keys to use with new provider
resource "authentik_certificate_key_pair" "authentik_self_signed" {
  name             = "jhaas-certificate-keypair"
  key_data         = tls_private_key.authentik_self_signed.private_key_pem
  certificate_data = tls_self_signed_cert.authentik_self_signed.cert_pem
}

#
########################
#
# Add Provider
#
########################
#

# The JHaaS Portal OAuth Provider
resource "authentik_provider_oauth2" "portal" {
  name = "jhaas-portal"

  client_id     = var.authentik_jhaas_client_id
  client_secret = var.authentik_jhaas_client_secret
  client_type   = "confidential"
  redirect_uris = [
    local.authentik_provider_redirect_uri
  ]

  signing_key = authentik_certificate_key_pair.authentik_self_signed.id
  sub_mode    = "user_id"

  authentication_flow = authentik_flow.auth.uuid
  authorization_flow  = authentik_flow.consent.uuid

  access_code_validity       = "minutes=1"
  access_token_validity      = "minutes=5"
  refresh_token_validity     = "days=30"
  include_claims_in_id_token = true
  issuer_mode                = "per_provider"

  property_mappings = [
    authentik_scope_mapping.email.id,
    authentik_scope_mapping.openid.id,
    authentik_scope_mapping.profile.id,
    authentik_scope_mapping.user_attributes.id
  ]
}

#
########################
#
# Add Application
#
########################
#

# The JHaaS Portal Application
resource "authentik_application" "portal" {
  name              = "jhaas-portal"
  slug              = "portal"
  protocol_provider = authentik_provider_oauth2.portal.id

  backchannel_providers = []
  open_in_new_tab       = false
  policy_engine_mode    = "any"
  group                 = ""

  meta_description = var.authentik_jhaas_slogan
  meta_icon        = var.authentik_branding_favicon
  meta_launch_url  = local.authentik_jhaas_launch_url
  meta_publisher   = var.authentik_branding_publisher
}

#
########################
#
# Add Tenant
#
########################
#

resource "authentik_brand" "jhaas" {
  domain  = var.authentik_domain
  default = true

  branding_title   = var.authentik_branding_title
  branding_favicon = var.authentik_branding_favicon
  branding_logo    = var.authentik_branding_logo

  flow_authentication = authentik_flow.auth.uuid
  flow_device_code    = ""
  flow_invalidation   = authentik_flow.logout.uuid
  flow_recovery       = authentik_flow.recovery.uuid
  flow_unenrollment   = ""
  flow_user_settings  = ""

  web_certificate = ""
  # event_retention = "days=365"
  attributes = jsonencode(
    {
      settings = {
        theme = {
          base = "light"
        }
      }
    }
  )
}
