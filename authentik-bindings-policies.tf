#
########################
#
# Add Policy Bindings
#
########################
#

# Binds Forced Login Redirect Policy to enrollment_2_enrollment_redirect_info binding
resource "authentik_policy_binding" "enrollment_force_login_redirect_2_enrollment" {
  target  = authentik_flow_stage_binding.enrollment_2_enrollment_redirect_info.id
  policy  = authentik_policy_expression.enrollment_force_login_redirect.id
  order   = 0
  enabled = true
  negate  = false
  timeout = 30
}

# Binds set_redirect Policy to logout_2_logout
resource "authentik_policy_binding" "set_redirect_2_logout" {
  target  = authentik_flow_stage_binding.logout_2_logout.id
  policy  = authentik_policy_expression.set_redirect.id
  order   = 0
  enabled = true
  negate  = false
  timeout = 30
}

# Binds Redirect-If-Unauth Policy to logout_2_logout
resource "authentik_policy_binding" "logout_redirect_if_unauth_2_logout" {
  target  = authentik_flow_stage_binding.logout_2_logout.id
  policy  = authentik_policy_expression.logout_redirect_if_unauth.id
  order   = 10
  enabled = true
  negate  = false
  timeout = 30
}

# Binds check_recovery_codes_presence Policy to consent_2_recovery_codes_missing
resource "authentik_policy_binding" "check_recovery_codes_presence_2_recovery_codes_missing" {
  target  = authentik_flow_stage_binding.consent_2_recovery_codes_missing.id
  policy  = authentik_policy_expression.check_recovery_codes_presence.id
  order   = 0
  enabled = true
  negate  = true
  timeout = 30
}

# Binds check_recovery_codes_presence Policy to consent_2_mfa_static_setup
resource "authentik_policy_binding" "check_recovery_codes_presence_2_mfa_static_setup" {
  target  = authentik_flow_stage_binding.consent_2_mfa_static_setup.id
  policy  = authentik_policy_expression.check_recovery_codes_presence.id
  order   = 0
  enabled = true
  negate  = true
  timeout = 30
}

# Binds check_recovery_codes_presence Policy to mfa_static_setup_2_recovery_codes_existing
resource "authentik_policy_binding" "check_recovery_codes_presence_2_recovery_codes_existing" {
  target  = authentik_flow_stage_binding.mfa_static_setup_2_recovery_codes_existing.id
  policy  = authentik_policy_expression.check_recovery_codes_presence.id
  order   = 0
  enabled = true
  negate  = false
  timeout = 30
}

# Binds check_recovery_codes_presence Policy to mfa_recovery_2_mfa_recovery_not_applicable
resource "authentik_policy_binding" "check_recovery_codes_presence_2_mfa_recovery_not_applicable" {
  target  = authentik_flow_stage_binding.mfa_recovery_2_mfa_recovery_not_applicable.id
  policy  = authentik_policy_expression.check_recovery_codes_presence.id
  order   = 0
  enabled = true
  negate  = true
  timeout = 30
}

###
# Redirect Policies for Configuration Stages
###

# Binds set_redirect Policy to totp_setup_2_totp_setup
resource "authentik_policy_binding" "set_redirect_2_totp_setup" {
  target  = authentik_flow_stage_binding.totp_setup_2_totp_setup.id
  policy  = authentik_policy_expression.set_redirect.id
  order   = 0
  enabled = true
  negate  = false
  timeout = 30
}

# Binds set_redirect Policy to webauthn_setup_2_webauthn_setup
resource "authentik_policy_binding" "set_redirect_2_webauthn_setup" {
  target  = authentik_flow_stage_binding.webauthn_setup_2_webauthn_setup.id
  policy  = authentik_policy_expression.set_redirect.id
  order   = 0
  enabled = true
  negate  = false
  timeout = 30
}

# Binds set_redirect Policy to mfa_static_setup_2_mfa_static_setup
resource "authentik_policy_binding" "set_redirect_2_mfa_static_setup" {
  target  = authentik_flow_stage_binding.mfa_static_setup_2_mfa_static_setup.id
  policy  = authentik_policy_expression.set_redirect.id
  order   = 0
  enabled = true
  negate  = false
  timeout = 30
}

# Binds set_redirect Policy to password_setup_2_password_setup_write
resource "authentik_policy_binding" "set_redirect_2_password_setup_write" {
  target  = authentik_flow_stage_binding.password_setup_2_password_setup_write.id
  policy  = authentik_policy_expression.set_redirect.id
  order   = 0
  enabled = true
  negate  = false
  timeout = 30
}
