#
########################
#
# Add FlowStage Bindings
#
########################
#

# Binds TOTP Setup Stage to TOTP Setup Flow
resource "authentik_flow_stage_binding" "totp_setup_2_totp_setup" {
  target                  = authentik_flow.totp_setup.uuid
  stage                   = authentik_stage_authenticator_totp.totp_setup.id
  order                   = 0
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = false
}

# Binds WebAuthn Setup Stage to WebAuthn Setup Flow
resource "authentik_flow_stage_binding" "webauthn_setup_2_webauthn_setup" {
  target                  = authentik_flow.webauthn_setup.uuid
  stage                   = authentik_stage_authenticator_webauthn.webauthn_setup.id
  order                   = 0
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = false
}

# Binds MFA Static Tokens Setup Stage to MFA Static Tokens Setup Flow
resource "authentik_flow_stage_binding" "mfa_static_setup_2_mfa_static_setup" {
  target                  = authentik_flow.mfa_static_setup.uuid
  stage                   = authentik_stage_authenticator_static.mfa_static_setup.id
  order                   = 0
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = false
}

# Binds Password Setup Prompt Stage to Password Setup Flow
resource "authentik_flow_stage_binding" "password_setup_2_password_setup_prompt" {
  target                  = authentik_flow.password_setup.uuid
  stage                   = authentik_stage_prompt.password_setup.id
  order                   = 0
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = false
}

# Binds Password Setup Write Stage to Password Setup Flow
resource "authentik_flow_stage_binding" "password_setup_2_password_setup_write" {
  target                  = authentik_flow.password_setup.uuid
  stage                   = authentik_stage_user_write.password_setup.id
  order                   = 10
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = false
}

# Binds TOS Stage to Enrollment Flow
resource "authentik_flow_stage_binding" "enrollment_2_enrollment_tos" {
  target                  = authentik_flow.enrollment.uuid
  stage                   = authentik_stage_prompt.enrollment_tos.id
  order                   = 10
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = false
}

# Binds User Prompt to Enrollment Flow
resource "authentik_flow_stage_binding" "enrollment_2_enrollment_user" {
  target                  = authentik_flow.enrollment.uuid
  stage                   = authentik_stage_prompt.enrollment_user.id
  order                   = 20
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = false
}

# Binds User Write Stage to Enrollment Flow
resource "authentik_flow_stage_binding" "enrollment_2_enrollment_write" {
  target                  = authentik_flow.enrollment.uuid
  stage                   = authentik_stage_user_write.enrollment_write.id
  order                   = 30
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = false
}

# Binds Email Stage to Enrollment Flow
resource "authentik_flow_stage_binding" "enrollment_2_enrollment_email" {
  target                  = authentik_flow.enrollment.uuid
  stage                   = authentik_stage_email.enrollment_email.id
  order                   = 40
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = false
}

# Binds Pre Recovery Codes Stage to Enrollment Flow
resource "authentik_flow_stage_binding" "enrollment_2_enrollment_pre_recovery_codes" {
  target                  = authentik_flow.enrollment.uuid
  stage                   = authentik_stage_prompt.enrollment_pre_recovery_codes.id
  order                   = 45
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = false
}

# Binds Recovery Codes Stage to Enrollment Flow
resource "authentik_flow_stage_binding" "enrollment_2_enrollment_recovery_codes" {
  target                  = authentik_flow.enrollment.uuid
  stage                   = authentik_stage_authenticator_static.enrollment_recovery_codes.id
  order                   = 50
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = false
}

# Binds Pre MFA Stage to Enrollment Flow
resource "authentik_flow_stage_binding" "enrollment_2_enrollment_pre_mfa" {
  target                  = authentik_flow.enrollment.uuid
  stage                   = authentik_stage_prompt.enrollment_pre_mfa.id
  order                   = 55
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = false
}

# Binds MFA Setup Stage to Enrollment Flow
resource "authentik_flow_stage_binding" "enrollment_2_enrollment_mfa_setup" {
  target                  = authentik_flow.enrollment.uuid
  stage                   = authentik_stage_authenticator_validate.enrollment_mfa_setup.id
  order                   = 60
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = false
}

# Binds Login Stage to Enrollment Flow
resource "authentik_flow_stage_binding" "enrollment_2_enrollment_login" {
  target                  = authentik_flow.enrollment.uuid
  stage                   = authentik_stage_user_login.enrollment_login.id
  order                   = 70
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = true
}

# Binds Identification Stage to Recovery Flow
resource "authentik_flow_stage_binding" "recovery_2_recovery_identification" {
  target                  = authentik_flow.recovery.uuid
  stage                   = authentik_stage_identification.recovery_identification.id
  order                   = 10
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = true
}

# Binds Email Stage to Recovery Flow
resource "authentik_flow_stage_binding" "recovery_2_recovery_email" {
  target                  = authentik_flow.recovery.uuid
  stage                   = authentik_stage_email.recovery_email.id
  order                   = 20
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = true
}

# Binds MFA Validation Stage to Recovery Flow
resource "authentik_flow_stage_binding" "recovery_2_recovery_mfa_validation" {
  target                  = authentik_flow.recovery.uuid
  stage                   = authentik_stage_authenticator_validate.recovery_mfa_validation.id
  order                   = 30
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = false
}

# Binds Prompt Stage to Recovery Flow
resource "authentik_flow_stage_binding" "recovery_2_recovery_prompt" {
  target                  = authentik_flow.recovery.uuid
  stage                   = authentik_stage_prompt.recovery_prompt.id
  order                   = 40
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = true
}

# Binds User Write Stage to Recovery Flow
resource "authentik_flow_stage_binding" "recovery_2_recovery_write" {
  target                  = authentik_flow.recovery.uuid
  stage                   = authentik_stage_user_write.recovery_write.id
  order                   = 50
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = true
}

# Binds Login Stage to Recovery Flow
resource "authentik_flow_stage_binding" "recovery_2_recovery_login" {
  target                  = authentik_flow.recovery.uuid
  stage                   = authentik_stage_user_login.recovery_login.id
  order                   = 60
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = true
}

# Binds Identification Stage to Auth Flow
resource "authentik_flow_stage_binding" "auth_2_auth_identification" {
  target                  = authentik_flow.auth.uuid
  stage                   = authentik_stage_identification.auth_identification.id
  order                   = 10
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = false
}

# Binds MFA Validation Stage to Auth Flow
resource "authentik_flow_stage_binding" "auth_2_auth_mfa_validate" {
  target                  = authentik_flow.auth.uuid
  stage                   = authentik_stage_authenticator_validate.auth_mfa_validate.id
  order                   = 20
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = false
}

# Binds Login Stage to Auth Flow
resource "authentik_flow_stage_binding" "auth_2_auth_login" {
  target                  = authentik_flow.auth.uuid
  stage                   = authentik_stage_user_login.auth_login.id
  order                   = 30
  invalid_response_action = "retry"
  policy_engine_mode      = "any"
  re_evaluate_policies    = true
  evaluate_on_plan        = false
}

# Binds Logout Stage to Logout Flow
resource "authentik_flow_stage_binding" "logout_2_logout" {
  target                  = authentik_flow.logout.uuid
  stage                   = authentik_stage_user_logout.logout.id
  order                   = 0
  invalid_response_action = "retry"
  policy_engine_mode      = "all"
  re_evaluate_policies    = true
  evaluate_on_plan        = true
}
