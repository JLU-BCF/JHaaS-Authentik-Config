#
########################
#
# Add Stages
#
########################
#

# Configuration Stage for TOTP Setup
resource "authentik_stage_authenticator_totp" "totp_setup" {
  name           = "📱 Setup Authenticator App"
  friendly_name  = "📱 Authenticator App"
  configure_flow = authentik_flow.totp_setup.uuid
  digits         = 6
}

# Configuration Stage for WebAuthn Setup
resource "authentik_stage_authenticator_webauthn" "webauthn_setup" {
  name           = "🛡️ Setup Security Device"
  friendly_name  = "🛡️ Security Device"
  configure_flow = authentik_flow.webauthn_setup.uuid

  resident_key_requirement = "preferred"
  user_verification        = "preferred"
}

# Configuration Stage for MFA Static Tokens Setup
resource "authentik_stage_authenticator_static" "mfa_static_setup" {
  name           = "🔑 Create Recovery Codes"
  friendly_name  = "🔑 Recovery Codes"
  configure_flow = authentik_flow.mfa_static_setup.uuid
  token_count    = 6
}

# Prompt Stage for initial password and password reset
resource "authentik_stage_prompt" "password_setup" {
  name = "jhaas-password-setup-prompt"
  fields = [
    resource.authentik_stage_prompt_field.setup_password.id,
    resource.authentik_stage_prompt_field.setup_password_repeat.id,
  ]
  validation_policies = [
    resource.authentik_policy_password.global_check_password.id
  ]
}

# Write Stage for initial password and password reset
resource "authentik_stage_user_write" "password_setup" {
  name               = "jhaas-password-setup-write"
  user_creation_mode = "never_create"
}

# Prompt Stage to show TOS and get acceptance
resource "authentik_stage_prompt" "enrollment_tos" {
  name = "jhaas-enrollment-tos"
  fields = [
    resource.authentik_stage_prompt_field.enrollment_tos_text.id,
    resource.authentik_stage_prompt_field.enrollment_tos_accept.id,
    resource.authentik_stage_prompt_field.back_to_login.id
  ]
  validation_policies = [
    resource.authentik_policy_expression.enrollment_check_tos.id
  ]
}

# Prompt Stage to get enrollment user details
resource "authentik_stage_prompt" "enrollment_user" {
  name = "jhaas-enrollment-user"
  fields = [
    resource.authentik_stage_prompt_field.enrollment_given_name.id,
    resource.authentik_stage_prompt_field.enrollment_family_name.id,
    resource.authentik_stage_prompt_field.enrollment_email.id,
    resource.authentik_stage_prompt_field.enrollment_password.id,
    resource.authentik_stage_prompt_field.back_to_login.id
  ]
  validation_policies = [
    resource.authentik_policy_expression.enrollment_check_username.id,
    resource.authentik_policy_expression.enrollment_map_attributes.id,
    resource.authentik_policy_password.global_check_password.id
  ]
}

# User Write Stage to save user
resource "authentik_stage_user_write" "enrollment_write" {
  name                     = "jhaas-enrollment-write"
  create_users_as_inactive = true
  create_users_group       = authentik_group.auth_untrusted.id
  user_creation_mode       = "always_create"
}

# Email Stage for email verification in enrollment
resource "authentik_stage_email" "enrollment_email" {
  name                     = "jhaas-enrollment-email"
  use_global_settings      = true
  activate_user_on_success = true
  subject                  = var.authentik_email_subject_enrollment
  template                 = var.authentik_email_template_enrollment
  token_expiry             = 30
}

# Prompt Stage to show information before showing recovery codes
resource "authentik_stage_prompt" "enrollment_pre_recovery_codes" {
  name = "jhaas-enrollment-pre-recovery-codes"
  fields = [
    resource.authentik_stage_prompt_field.enrollment_recovery_codes_text.id
  ]
}

# Prompt Stage to show information before setting up MFA
resource "authentik_stage_prompt" "enrollment_pre_mfa" {
  name = "jhaas-enrollment-pre-mfa"
  fields = [
    resource.authentik_stage_prompt_field.enrollment_mfa_text.id
  ]
}

# Stage to validate (in terms of enrollment: setup) mfa
resource "authentik_stage_authenticator_validate" "enrollment_mfa_setup" {
  name           = "jhaas-enrollment-mfa-setup"
  device_classes = ["totp", "webauthn"]

  not_configured_action      = "configure"
  webauthn_user_verification = "required"
  last_auth_threshold        = "seconds=0"

  configuration_stages = [
    authentik_stage_authenticator_totp.totp_setup.id,
    authentik_stage_authenticator_webauthn.webauthn_setup.id
  ]
}

# Login Stage to automatically login user after enrollment
resource "authentik_stage_user_login" "enrollment_login" {
  name = "jhaas-enrollment-login"

  remember_me_offset = "seconds=0"
  session_duration   = "seconds=0"
}

# Prompt Stage after Login to initiate redirect
resource "authentik_stage_prompt" "enrollment_redirect_info" {
  name = "jhaas-enrollment-redirect-info"
  fields = [
    resource.authentik_stage_prompt_field.enrollment_redirect_info.id
  ]
}

# Identification Stage for password recovery
resource "authentik_stage_identification" "recovery_identification" {
  name                      = "jhaas-recovery-identification"
  user_fields               = ["email"]
  case_insensitive_matching = true
  show_matched_user         = false
  show_source_labels        = false

  enrollment_flow = authentik_flow.enrollment.uuid
  recovery_flow   = authentik_flow.recovery.uuid
}

# Email Stage for password recovery
resource "authentik_stage_email" "recovery_email" {
  name                     = "jhaas-recovery-email"
  use_global_settings      = true
  activate_user_on_success = true
  subject                  = var.authentik_email_subject_recovery
  template                 = var.authentik_email_template_recovery
  token_expiry             = 30
}

# MFA Stage without Static Codes for Password Recovery
resource "authentik_stage_authenticator_validate" "recovery_mfa_validation" {
  name                  = "jhaas-recovery-mfa-validation"
  device_classes        = ["totp", "webauthn"]
  not_configured_action = "deny"
  last_auth_threshold   = "seconds=0"
}

# Prompt stage to get passwords
resource "authentik_stage_prompt" "recovery_prompt" {
  name = "jhaas-recovery-prompt"
  fields = [
    authentik_stage_prompt_field.recovery_password.id,
    authentik_stage_prompt_field.recovery_password_repeat.id
  ]
  validation_policies = [
    resource.authentik_policy_password.global_check_password.id
  ]
}

# User write stage for Password Recovery
resource "authentik_stage_user_write" "recovery_write" {
  name               = "jhaas-recovery-write"
  user_creation_mode = "never_create"
}

# Login after password reset
resource "authentik_stage_user_login" "recovery_login" {
  name = "jhaas-recovery-login"

  remember_me_offset = "seconds=0"
  session_duration   = "seconds=0"
}

# Password Stage for Authentication
resource "authentik_stage_password" "auth_password" {
  name                          = "jhaas-auth-password"
  backends                      = ["authentik.core.auth.InbuiltBackend"]
  configure_flow                = authentik_flow.password_setup.uuid
  failed_attempts_before_cancel = 5
}

# Identification Stage for Authentication
resource "authentik_stage_identification" "auth_identification" {
  name                      = "jhaas-auth-identification"
  user_fields               = ["email"]
  case_insensitive_matching = true
  show_matched_user         = false
  show_source_labels        = false

  enrollment_flow = authentik_flow.enrollment.uuid
  recovery_flow   = authentik_flow.recovery.uuid
  password_stage  = authentik_stage_password.auth_password.id
}

# Stage to validate mfa in Authentication
resource "authentik_stage_authenticator_validate" "auth_mfa_validate" {
  name           = "jhaas-auth-mfa-validate"
  device_classes = ["totp", "webauthn", "static"]

  not_configured_action      = "configure"
  webauthn_user_verification = "preferred"
  last_auth_threshold        = "seconds=0"

  configuration_stages = [
    authentik_stage_authenticator_totp.totp_setup.id,
    authentik_stage_authenticator_webauthn.webauthn_setup.id,
    authentik_stage_authenticator_static.mfa_static_setup.id,
  ]
}

# Login after successfull authentication
resource "authentik_stage_user_login" "auth_login" {
  name = "jhaas-auth-login"

  remember_me_offset = "seconds=0"
  session_duration   = "seconds=0"
}

# Logout after successfull invalidation
resource "authentik_stage_user_logout" "logout" {
  name = "jhaas-logout"
}
