#
########################
#
# Add Flows
#
########################
#

# Flow to setup MFA with a TOTP Generator
resource "authentik_flow" "totp_setup" {
  name               = "jhaas-totp-setup"
  title              = "Setup Authenticator App"
  slug               = "totp-setup"
  designation        = "stage_configuration"
  authentication     = "require_authenticated"
  denied_action      = "message_continue"
  layout             = "stacked"
  policy_engine_mode = "any"
  compatibility_mode = true
  background         = var.authentik_flow_background
}

# Flow to setup MFA with a WebAuthn Device
resource "authentik_flow" "webauthn_setup" {
  name               = "jhaas-webauthn-setup"
  title              = "Setup WebAuthn Device"
  slug               = "webauthn-setup"
  designation        = "stage_configuration"
  authentication     = "require_authenticated"
  denied_action      = "message_continue"
  layout             = "stacked"
  policy_engine_mode = "any"
  compatibility_mode = true
  background         = var.authentik_flow_background
}

# Flow to setup MFA with static codes
resource "authentik_flow" "mfa_static_setup" {
  name               = "jhaas-mfa-static-setup"
  title              = "Recovery Codes"
  slug               = "mfa-static-setup"
  designation        = "stage_configuration"
  authentication     = "require_authenticated"
  denied_action      = "message_continue"
  layout             = "stacked"
  policy_engine_mode = "any"
  compatibility_mode = true
  background         = var.authentik_flow_background
}

# Flow to setup initial Password or Password Reset
resource "authentik_flow" "password_setup" {
  name               = "jhaas-password-setup"
  title              = "Setup your Password"
  slug               = "password-setup"
  designation        = "stage_configuration"
  authentication     = "require_authenticated"
  denied_action      = "message_continue"
  layout             = "stacked"
  policy_engine_mode = "any"
  compatibility_mode = true
  background         = var.authentik_flow_background
}

# Flow to self enroll user accounts
resource "authentik_flow" "enrollment" {
  name               = "jhaas-enrollment"
  title              = "Sign Up"
  slug               = "enrollment"
  designation        = "enrollment"
  authentication     = "require_unauthenticated"
  denied_action      = "message_continue"
  layout             = "stacked"
  policy_engine_mode = "any"
  compatibility_mode = true
  background         = var.authentik_flow_background
}

# Flow to reset password
resource "authentik_flow" "recovery" {
  name               = "jhaas-recovery"
  title              = "Reset your Password"
  slug               = "password-recovery"
  designation        = "recovery"
  authentication     = "require_unauthenticated"
  denied_action      = "message_continue"
  layout             = "stacked"
  policy_engine_mode = "any"
  compatibility_mode = true
  background         = var.authentik_flow_background
}

# Flow to reset MFA
resource "authentik_flow" "mfa_recovery" {
  name               = "jhaas-mfa-recovery"
  title              = "Reset Multi-Factor Authentication"
  slug               = "mfa-recovery"
  designation        = "recovery"
  authentication     = "require_unauthenticated"
  denied_action      = "message_continue"
  layout             = "stacked"
  policy_engine_mode = "any"
  compatibility_mode = true
  background         = var.authentik_flow_background
}

# Flow to authenticate user
resource "authentik_flow" "auth" {
  name               = "jhaas-auth"
  title              = "Login"
  slug               = "auth"
  designation        = "authentication"
  authentication     = "none"
  denied_action      = "message_continue"
  layout             = "stacked"
  policy_engine_mode = "any"
  compatibility_mode = true
  background         = var.authentik_flow_background
}

# Flow to logout user
resource "authentik_flow" "logout" {
  name               = "jhaas-logout"
  title              = "Logout"
  slug               = "logout"
  designation        = "invalidation"
  authentication     = "none"
  denied_action      = "message_continue"
  layout             = "stacked"
  policy_engine_mode = "any"
  compatibility_mode = true
  background         = var.authentik_flow_background
}

# Flow to implicitly consent to jhaas
resource "authentik_flow" "consent" {
  name               = "jhaas-consent"
  title              = "Attention Required"
  slug               = "consent"
  designation        = "authorization"
  authentication     = "require_authenticated"
  denied_action      = "message_continue"
  layout             = "stacked"
  policy_engine_mode = "any"
  compatibility_mode = true
  background         = var.authentik_flow_background
}
