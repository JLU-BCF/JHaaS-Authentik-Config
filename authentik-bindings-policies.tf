#
########################
#
# Add Policy Bindings
#
########################
#

# Binds Login Redirect Policy to enrollment_2_enrollment_login binding
resource "authentik_policy_binding" "enrollment_login_redirect_2_enrollment" {
  target  = authentik_flow_stage_binding.enrollment_2_enrollment_login.id
  policy  = authentik_policy_expression.enrollment_login_redirect.id
  order   = 0
  enabled = true
  negate  = false
  timeout = 30
}

# Binds Check Username Policy to enrollment_2_enrollment_cancel
resource "authentik_policy_binding" "enrollment_check_username_2_enrollment" {
  target  = authentik_flow_stage_binding.enrollment_2_enrollment_cancel.id
  policy  = authentik_policy_expression.enrollment_check_username.id
  order   = 10
  enabled = true
  negate  = true
  timeout = 30
}

# Binds Map Attributes Policy to enrollment_2_enrollment_cancel
resource "authentik_policy_binding" "enrollment_map_attributes_2_enrollment" {
  target  = authentik_flow_stage_binding.enrollment_2_enrollment_cancel.id
  policy  = authentik_policy_expression.enrollment_map_attributes.id
  order   = 20
  enabled = true
  negate  = true
  timeout = 30
}

# Binds Redirect-If-Restored Policy to recovery_2_recovery_identification
resource "authentik_policy_binding" "recovery_skip_if_restored_2_recovery" {
  target  = authentik_flow_stage_binding.recovery_2_recovery_identification.id
  policy  = authentik_policy_expression.recovery_skip_if_restored.id
  order   = 0
  enabled = true
  negate  = false
  timeout = 30
}

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
