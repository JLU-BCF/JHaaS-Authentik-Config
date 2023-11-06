#
########################
#
# Add Policy Bindings
#
########################
#

# Binds Login Redirect Policy to enrollment_2_enrollment_login binding
# resource "authentik_policy_binding" "enrollment_login_redirect_2_enrollment" {
#   target  = authentik_flow_stage_binding.enrollment_2_enrollment_login.id
#   policy  = authentik_policy_expression.enrollment_login_redirect.id
#   order   = 0
#   enabled = true
#   negate  = false
#   timeout = 30
# }

# Binds Forced Login Redirect Policy to enrollment_2_enrollment_redirect_info binding
resource "authentik_policy_binding" "enrollment_force_login_redirect_2_enrollment" {
  target  = authentik_flow_stage_binding.enrollment_2_enrollment_redirect_info.id
  policy  = authentik_policy_expression.enrollment_force_login_redirect.id
  order   = 0
  enabled = true
  negate  = false
  timeout = 30
}

# # Binds Redirect-If-Restored Policy to recovery_2_recovery_identification
# resource "authentik_policy_binding" "recovery_skip_if_restored_2_recovery" {
#   target  = authentik_flow_stage_binding.recovery_2_recovery_identification.id
#   policy  = authentik_policy_expression.recovery_skip_if_restored.id
#   order   = 0
#   enabled = true
#   negate  = false
#   timeout = 30
# }

# Binds Set-Redirect-Url Policy to logout_2_logout
resource "authentik_policy_binding" "logout_set_redirect_url_2_logout" {
  target  = authentik_flow_stage_binding.logout_2_logout.id
  policy  = authentik_policy_expression.logout_set_redirect_url.id
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

# Binds check_recovery_codes_presence Policy to mfa_recovery_2_deny
resource "authentik_policy_binding" "check_recovery_codes_presence_2_deny" {
  target  = authentik_flow_stage_binding.mfa_recovery_2_deny.id
  policy  = authentik_policy_expression.check_recovery_codes_presence.id
  order   = 0
  enabled = true
  negate  = true
  timeout = 30
}

# Binds force_home_redirect Policy to mfa_recovery_2_deny
resource "authentik_policy_binding" "force_home_redirect_2_deny" {
  target  = authentik_flow_stage_binding.mfa_recovery_2_deny.id
  policy  = authentik_policy_expression.force_home_redirect.id
  order   = 10
  enabled = true
  negate  = false
  timeout = 30
}
