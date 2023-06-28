provider "authentik" {
  url = var.authentik_url
  token = var.authentik_token
}

#
########################
#
# Add Groups
#
########################
#

# Group to identify the government
resource "authentik_group" "portal_admins" {
  name         = "portal-admins"
}

# Group to identify leaders
resource "authentik_group" "portal_leaders" {
  name         = "portal-leaders"
}

# Group attached to users validated with trusted Source (e.g. LDAP)
resource "authentik_group" "auth_trusted" {
  name         = "auth-trusted"
}

# Group attached to self registered users
resource "authentik_group" "auth_untrusted" {
  name         = "auth-untrusted"
}

#
########################
#
# Add Flows
#
########################
#

# Flow to setup MFA with a TOTP Generator
resource "authentik_flow" "totp_setup" {
  name                = "jhaas-totp-setup"
  title               = "Setup Authenticator App"
  slug                = "totp-setup"
  designation         = "stage_configuration"
  authentication      = "require_authenticated"
  denied_action       = "message_continue"
  layout              = "stacked"
  policy_engine_mode  = "any"
  compatibility_mode  = true
  background          = var.authentik_flow_background
}

# Flow to setup MFA with a WebAuthn Device
resource "authentik_flow" "webauthn_setup" {
  name                = "jhaas-webauthn-setup"
  title               = "Setup WebAuthn Device"
  slug                = "webauthn-setup"
  designation         = "stage_configuration"
  authentication      = "require_authenticated"
  denied_action       = "message_continue"
  layout              = "stacked"
  policy_engine_mode  = "any"
  compatibility_mode  = true
  background          = var.authentik_flow_background
}

# Flow to setup MFA with static tokens
resource "authentik_flow" "mfa_static_setup" {
  name                = "jhaas-mfa-static-setup"
  title               = "Recovery Codes"
  slug                = "mfa-static-setup"
  designation         = "stage_configuration"
  authentication      = "require_authenticated"
  denied_action       = "message_continue"
  layout              = "stacked"
  policy_engine_mode  = "any"
  compatibility_mode  = true
  background          = var.authentik_flow_background
}

# Flow to setup initial Password or Password Reset
resource "authentik_flow" "password_setup" {
  name                = "jhaas-password-setup"
  title               = "Setup your Password"
  slug                = "password-setup"
  designation         = "stage_configuration"
  authentication      = "require_authenticated"
  denied_action       = "message_continue"
  layout              = "stacked"
  policy_engine_mode  = "any"
  compatibility_mode  = true
  background          = var.authentik_flow_background
}

# Flow to self enroll user accounts
resource "authentik_flow" "enrollment" {
  name                = "jhaas-enrollment"
  title               = "Sign Up"
  slug                = "enrollment"
  designation         = "enrollment"
  authentication      = "require_unauthenticated"
  denied_action       = "message_continue"
  layout              = "stacked"
  policy_engine_mode  = "any"
  compatibility_mode  = true
  background          = var.authentik_flow_background
}

# Flow to reset password
resource "authentik_flow" "recovery" {
  name                = "jhaas-recovery"
  title               = "Reset your Password"
  slug                = "password-recovery"
  designation         = "recovery"
  authentication      = "require_unauthenticated"
  denied_action       = "message_continue"
  layout              = "stacked"
  policy_engine_mode  = "any"
  compatibility_mode  = true
  background          = var.authentik_flow_background
}

# Flow to authenticate user
resource "authentik_flow" "auth" {
  name                = "jhaas-auth"
  title               = "Login"
  slug                = "auth"
  designation         = "authentication"
  authentication      = "none"
  denied_action       = "message_continue"
  layout              = "stacked"
  policy_engine_mode  = "any"
  compatibility_mode  = true
  background          = var.authentik_flow_background
}

# Flow to logout user
resource "authentik_flow" "logout" {
  name                = "jhaas-logout"
  title               = "Logout"
  slug                = "logout"
  designation         = "invalidation"
  authentication      = "none"
  denied_action       = "message_continue"
  layout              = "stacked"
  policy_engine_mode  = "any"
  compatibility_mode  = true
  background          = var.authentik_flow_background
}

# Flow to implicitly consent to jhaas
resource "authentik_flow" "consent" {
  name                = "jhaas-consent"
  title               = "Consent"
  slug                = "consent"
  designation         = "authorization"
  authentication      = "require_authenticated"
  denied_action       = "message_continue"
  layout              = "stacked"
  policy_engine_mode  = "any"
  compatibility_mode  = true
  background          = var.authentik_flow_background
}

#
########################
#
# Add Prompts
#
########################
#

# Setup Password field for initial password setup and password reset
resource "authentik_stage_prompt_field" "setup_password" {
  name        = "jhaas-setup-password"
  label       = "Password"
  placeholder = "Password"
  field_key   = "password"
  type        = "password"
  order       = 300
  required    = true
}

# Setup Password Repeat field for initial password setup and password reset
resource "authentik_stage_prompt_field" "setup_password_repeat" {
  name        = "jhaas-setup-password-repeat"
  label       = "Password (repeat)"
  placeholder = "Password (repeat)"
  field_key   = "password_repeat"
  type        = "password"
  order       = 301
  required    = true
}

# Setup TOS text field for enrollment
resource "authentik_stage_prompt_field" "enrollment_tos_text" {
  name        = "jhaas-enrollment-tos-text"
  label       = "Terms of service"
  field_key   = "tos_text"
  type        = "static"
  order       = 0
  required    = true
  sub_text    = <<-TOS_TEXT
      You are about to create an account for JHaaS. This is a prototype and
      we do not assume any liability or warranty for anything. Your data will not
      be shared with any third party and will be completely removed once the prototype
      stage is over. Read the <a target="_blank" href="${var.authentik_tos_url}">terms
      of use.</a>
  TOS_TEXT
}

# Setup TOS acceptance field for enrollment
resource "authentik_stage_prompt_field" "enrollment_tos_accept" {
  name        = "jhaas-enrollment-tos-accept"
  label       = "I accept the terms of service"
  field_key   = "tos_accept"
  type        = "checkbox"
  order       = 5
  required    = true
}

# Setup Given Name field for enrollment
resource "authentik_stage_prompt_field" "enrollment_given_name" {
  name        = "jhaas-enrollment-given-name"
  label       = "Given Name"
  placeholder = "Given Name"
  field_key   = "givenname"
  type        = "text"
  order       = 0
  required    = true
}

# Setup Family Name field for enrollment
resource "authentik_stage_prompt_field" "enrollment_family_name" {
  name        = "jhaas-enrollment-family-name"
  label       = "Family Name"
  placeholder = "Family Name"
  field_key   = "familyname"
  type        = "text"
  order       = 1
  required    = true
}

# Setup Email field for enrollment
resource "authentik_stage_prompt_field" "enrollment_email" {
  name        = "jhaas-enrollment-email"
  label       = "Email address"
  placeholder = "Email address"
  field_key   = "email"
  type        = "email"
  order       = 2
  required    = true
}

# Setup Password field for enrollment
resource "authentik_stage_prompt_field" "enrollment_password" {
  name        = "jhaas-enrollment-password"
  label       = "Password"
  placeholder = "Password"
  field_key   = "password"
  type        = "password"
  order       = 4
  required    = true
}

# Setup Pre Recovery Codes Text field for enrollment
resource "authentik_stage_prompt_field" "enrollment_recovery_codes_text" {
  name        = "jhaas-enrollment-revocery-codes-text"
  label       = "Information about recovery codes"
  field_key   = "revocery_codes_text"
  type        = "static"
  order       = 0
  required    = true
  sub_text    = <<-TOKEN_TEXT
      The next step is to set up multi-factor authentication. First, static
      recovery tokens are generated for you. It is important to keep these tokens
      safe (e.g. print them out) to be able to reset the account in case a second
      factor is lost.
  TOKEN_TEXT
}

# Setup Pre MFA Setup Text field for enrollment
resource "authentik_stage_prompt_field" "enrollment_mfa_text" {
  name        = "jhaas-enrollment-mfa-text"
  label       = "Information about MFA"
  field_key   = "mfa_text"
  type        = "static"
  order       = 0
  required    = true
  sub_text    = <<-MFA_TEXT
      In the next step, you select a second factor. This can be done either
      with an Authenticator app (a QR code will be displayed which has to be scanned
      with the Authenticator app) or with a WebAuthn device such as a Yubikey.
  MFA_TEXT
}

# Setup Password Prompt field for password recovery
resource "authentik_stage_prompt_field" "recovery_password" {
  name        = "jhaas-recovery-password"
  label       = "Password"
  placeholder = "Password"
  field_key   = "password"
  type        = "password"
  order       = 10
  required    = true
}

# Setup Password Repeat Prompt field for password recovery
resource "authentik_stage_prompt_field" "recovery_password_repeat" {
  name        = "jhaas-recovery-password-repeat"
  label       = "Password (repeat)"
  placeholder = "Password (repeat)"
  field_key   = "password_repeat"
  type        = "password"
  order       = 20
  required    = true
}

#
########################
#
# Add Policies
#
########################
#

# Policy to set login redirect for jhaas as it gets lost in enrollment flow
# when user navigates away to confirm the email address
resource "authentik_policy_expression" "enrollment_login_redirect" {
  name              = "jhaas-enrollment-login-redirect"
  execution_logging = true
  expression        = <<-LOGIN_REDIRECT
      context['flow_plan'].context['redirect'] = "${var.authentik_jhaas_login_redirect}"
      return True
  LOGIN_REDIRECT
}

# Policy to check if username is available
resource "authentik_policy_expression" "enrollment_check_username" {
  name              = "jhaas-enrollment-check-username"
  execution_logging = true
  expression        = <<-CHECK_USERNAME
      check_user_username = ak_user_by(username=context['prompt_data']['email'])
      check_user_email = ak_user_by(email=context['prompt_data']['email'])

      if check_user_username or check_user_email:
        ak_message('This email address has already been taken, you may login instead.')
        plan = request.context.get("flow_plan")
        if not plan:
          return False
        plan.redirect("${var.authentik_jhaas_login_flow}")
        return False

      return True
  CHECK_USERNAME
}

# Policy to map username and attributes
resource "authentik_policy_expression" "enrollment_map_attributes" {
  name              = "jhaas-enrollment-map-attributes"
  execution_logging = true
  expression        = <<-MAP_ATTRIBUTES
      context['prompt_data']['username'] = context['prompt_data']['email']

      context['prompt_data']['name'] = context['prompt_data']['givenname'] + ' ' + context['prompt_data']['familyname']

      context['prompt_data']['attributes'] = {}
      context['prompt_data']['attributes']['given_name'] = context['prompt_data']['givenname']
      context['prompt_data']['attributes']['family_name'] = context['prompt_data']['familyname']


      return True
  MAP_ATTRIBUTES
}

# Policy to check if this is a restored session
resource "authentik_policy_expression" "recovery_skip_if_restored" {
  name              = "jhaas-recovery-skip-if-restored"
  execution_logging = true
  expression        = <<-SKIP_IF_RESTORED
      return bool(request.context.get('is_restored', True))
  SKIP_IF_RESTORED
}

# Policy to set redirect url
resource "authentik_policy_expression" "logout_set_redirect_url" {
  name              = "jhaas-logout-set-redirect-url"
  execution_logging = true
  expression        = <<-SET_REDIRECT_URL
      context['flow_plan'].context['redirect'] = "${var.authentik_jhaas_verify_redirect}"

      return True
  SET_REDIRECT_URL
}

# Policy to redirect user if already logged out
resource "authentik_policy_expression" "logout_redirect_if_unauth" {
  name              = "jhaas-logout-redirect-if-unauth"
  execution_logging = true
  expression        = <<-REDIRECT_IF_UNAUTH
      if request.user and request.user.is_authenticated:
        return True

      plan = request.context.get("flow_plan")
      if not plan:
        return False

      plan.redirect("${var.authentik_jhaas_verify_redirect}")
      return False
  REDIRECT_IF_UNAUTH
}

#
########################
#
# Add Stages
#
########################
#

# Configuration Stage for TOTP Setup
resource "authentik_stage_authenticator_totp" "totp_setup" {
  name = "jhaas-totp-setup"
  friendly_name = "Use Authenticator App"
  configure_flow = authentik_flow.totp_setup.uuid
  digits = 6
}

# Configuration Stage for WebAuthn Setup
resource "authentik_stage_authenticator_webauthn" "webauthn_setup" {
  name = "jhaas-webauthn-setup"
  friendly_name = "Use WebAuthn Device"
  configure_flow = authentik_flow.webauthn_setup.uuid
  resident_key_requirement = "preferred"
  user_verification = "preferred"
}

# Configuration Stage for MFA Static Tokens Setup
resource "authentik_stage_authenticator_static" "mfa_static_setup" {
  name = "jhaas-mfa-static-setup"
  friendly_name = "Recovery Codes"
  configure_flow = authentik_flow.mfa_static_setup.uuid
  token_count = 6
}

# Prompt Stage for initial password and password reset
resource "authentik_stage_prompt" "password_setup" {
  name = "jhaas-password-setup-prompt"
  fields = [
    resource.authentik_stage_prompt_field.setup_password.id,
    resource.authentik_stage_prompt_field.setup_password_repeat.id,
  ]
}

# Write Stage for initial password and password reset
resource "authentik_stage_user_write" "password_setup" {
  name                = "jhaas-password-setup-write"
  user_creation_mode  = "never_create"
}

# Prompt Stage to show TOS and get acceptance
resource "authentik_stage_prompt" "enrollment_tos" {
  name = "jhaas-enrollment-tos"
  fields = [
    resource.authentik_stage_prompt_field.enrollment_tos_text.id,
    resource.authentik_stage_prompt_field.enrollment_tos_accept.id
  ]
}

# Prompt Stage to get enrollment user details
resource "authentik_stage_prompt" "enrollment_user" {
  name = "jhaas-enrollment-user"
  fields = [
    resource.authentik_stage_prompt_field.enrollment_given_name.id,
    resource.authentik_stage_prompt_field.enrollment_family_name.id,
    resource.authentik_stage_prompt_field.enrollment_email.id,
    resource.authentik_stage_prompt_field.enrollment_password.id
  ]
}

# Deny Stage for cancelling enrollment
resource "authentik_stage_deny" "enrollment_cancel" {
  name = "jhaas-enrollment-cancel"
}

# User Write Stage to save user
resource "authentik_stage_user_write" "enrollment_write" {
  name                      = "jhaas-enrollment-write"
  create_users_as_inactive  = true
  create_users_group        = authentik_group.auth_untrusted.id
  user_creation_mode        = "always_create"
}

# Email Stage for email verification in enrollment
resource "authentik_stage_email" "enrollment_email" {
  name = "jhaas-enrollment-email"
  use_global_settings = true
  activate_user_on_success = true
  subject = var.authentik_email_subject_enrollment
  template = var.authentik_email_template_enrollment
  token_expiry = 30
}

# Prompt Stage to show information before showing recovery codes
resource "authentik_stage_prompt" "enrollment_pre_recovery_codes" {
  name = "jhaas-enrollment-pre-recovery-codes"
  fields = [
    resource.authentik_stage_prompt_field.enrollment_recovery_codes_text.id
  ]
}

# Stage to setup static recovery codes for enrollment
resource "authentik_stage_authenticator_static" "enrollment_recovery_codes" {
  name            = "jhaas-enrollment-recovery-codes"
  configure_flow  = authentik_flow.mfa_static_setup.uuid
  friendly_name   = "Static Recovery Codes"
  token_count     = 6
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
  name                        = "jhaas-enrollment-mfa-setup"
  device_classes              = ["totp", "webauthn"]
  not_configured_action       = "configure"
  webauthn_user_verification  = "required"
  last_auth_threshold         = "seconds=0"
  configuration_stages        = [
    authentik_stage_authenticator_totp.totp_setup.id,
    authentik_stage_authenticator_webauthn.webauthn_setup.id
  ]
}

# Login Stage to automatically login user after enrollment
resource "authentik_stage_user_login" "enrollment_login" {
  name                = "jhaas-enrollment-login"
  remember_me_offset  = "seconds=0"
  session_duration    = "seconds=0"
}

# Identification Stage for password recovery
resource "authentik_stage_identification" "recovery_identification" {
  name                      = "jhaas-recovery-identification"
  user_fields               = ["email"]
  case_insensitive_matching = true
  show_matched_user         = false
}

# Email Stage for password recovery
resource "authentik_stage_email" "recovery_email" {
  name = "jhaas-recovery-email"
  use_global_settings = true
  activate_user_on_success = true
  subject = var.authentik_email_subject_recovery
  template = var.authentik_email_template_recovery
  token_expiry = 30
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
}

# User write stage for Password Recovery
resource "authentik_stage_user_write" "recovery_write" {
  name                = "jhaas-recovery-write"
  user_creation_mode  = "never_create"
}

# Login after password reset
resource "authentik_stage_user_login" "recovery_login" {
  name                = "jhaas-recovery-login"
  remember_me_offset  = "seconds=0"
  session_duration    = "seconds=0"
}

# Password Stage for Authentication
resource "authentik_stage_password" "auth_password" {
  name     = "jhaas-auth-password"
  backends = ["authentik.core.auth.InbuiltBackend"]
  configure_flow = authentik_flow.password_setup.uuid
  failed_attempts_before_cancel = 5
}

# Identification Stage for Authentication
resource "authentik_stage_identification" "auth_identification" {
  name                      = "jhaas-auth-identification"
  user_fields               = ["email"]
  case_insensitive_matching = true
  show_matched_user         = false
  show_source_labels        = false

  enrollment_flow           = authentik_flow.enrollment.id
  recovery_flow             = authentik_flow.recovery.id
  password_stage            = authentik_stage_password.auth_password.id
}

# Stage to validate mfa in Authentication
resource "authentik_stage_authenticator_validate" "auth_mfa_validate" {
  name                        = "jhaas-auth-mfa-validate"
  device_classes              = ["totp", "webauthn", "static"]
  not_configured_action       = "configure"
  webauthn_user_verification  = "preferred"
  last_auth_threshold         = "seconds=0"
  configuration_stages        = [
    authentik_stage_authenticator_totp.totp_setup.id,
    authentik_stage_authenticator_webauthn.webauthn_setup.id,
    authentik_stage_authenticator_static.mfa_static_setup.id,
  ]
}

# Login after successfull authentication
resource "authentik_stage_user_login" "auth_login" {
  name                = "jhaas-auth-login"
  remember_me_offset  = "seconds=0"
  session_duration    = "seconds=0"
}

# Logout after successfull invalidation
resource "authentik_stage_user_logout" "logout" {
  name = "jhaas-logout"
}

#
########################
#
# Add FlowStage Bindings
#
########################
#

# Binds TOTP Setup Stage to TOTP Setup Flow
resource "authentik_flow_stage_binding" "totp_setup_2_totp_setup" {
  target = authentik_flow.totp_setup.uuid
  stage  = authentik_stage_authenticator_totp.totp_setup.id
  order  = 0
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = false
}

# Binds WebAuthn Setup Stage to WebAuthn Setup Flow
resource "authentik_flow_stage_binding" "webauthn_setup_2_webauthn_setup" {
  target = authentik_flow.webauthn_setup.uuid
  stage  = authentik_stage_authenticator_webauthn.webauthn_setup.id
  order  = 0
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = false
}

# Binds MFA Static Tokens Setup Stage to MFA Static Tokens Setup Flow
resource "authentik_flow_stage_binding" "mfa_static_setup_2_mfa_static_setup" {
  target = authentik_flow.mfa_static_setup.uuid
  stage  = authentik_stage_authenticator_static.mfa_static_setup.id
  order  = 0
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = false
}

# Binds Password Setup Prompt Stage to Password Setup Flow
resource "authentik_flow_stage_binding" "password_setup_2_password_setup_prompt" {
  target = authentik_flow.password_setup.uuid
  stage  = authentik_stage_prompt.password_setup.id
  order  = 0
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = false
}

# Binds Password Setup Write Stage to Password Setup Flow
resource "authentik_flow_stage_binding" "password_setup_2_password_setup_write" {
  target = authentik_flow.password_setup.uuid
  stage  = authentik_stage_user_write.password_setup.id
  order  = 10
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = false
}

# Binds TOS Stage to Enrollment Flow
resource "authentik_flow_stage_binding" "enrollment_2_enrollment_tos" {
  target = authentik_flow.enrollment.uuid
  stage  = authentik_stage_prompt.enrollment_tos.id
  order  = 10
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = false
}

# Binds User Prompt to Enrollment Flow
resource "authentik_flow_stage_binding" "enrollment_2_enrollment_user" {
  target = authentik_flow.enrollment.uuid
  stage  = authentik_stage_prompt.enrollment_user.id
  order  = 20
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = false
}

# Binds Deny Stage to Enrollment Flow
resource "authentik_flow_stage_binding" "enrollment_2_enrollment_cancel" {
  target = authentik_flow.enrollment.uuid
  stage  = authentik_stage_deny.enrollment_cancel.id
  order  = 25
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = false
}

# Binds User Write Stage to Enrollment Flow
resource "authentik_flow_stage_binding" "enrollment_2_enrollment_write" {
  target = authentik_flow.enrollment.uuid
  stage  = authentik_stage_user_write.enrollment_write.id
  order  = 30
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = false
}

# Binds Email Stage to Enrollment Flow
resource "authentik_flow_stage_binding" "enrollment_2_enrollment_email" {
  target = authentik_flow.enrollment.uuid
  stage  = authentik_stage_email.enrollment_email.id
  order  = 40
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = false
}

# Binds Pre Recovery Codes Stage to Enrollment Flow
resource "authentik_flow_stage_binding" "enrollment_2_enrollment_pre_recovery_codes" {
  target = authentik_flow.enrollment.uuid
  stage  = authentik_stage_prompt.enrollment_pre_recovery_codes.id
  order  = 45
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = false
}

# Binds Recovery Codes Stage to Enrollment Flow
resource "authentik_flow_stage_binding" "enrollment_2_enrollment_recovery_codes" {
  target = authentik_flow.enrollment.uuid
  stage  = authentik_stage_authenticator_static.enrollment_recovery_codes.id
  order  = 50
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = false
}

# Binds Pre MFA Stage to Enrollment Flow
resource "authentik_flow_stage_binding" "enrollment_2_enrollment_pre_mfa" {
  target = authentik_flow.enrollment.uuid
  stage  = authentik_stage_prompt.enrollment_pre_mfa.id
  order  = 55
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = false
}

# Binds MFA Setup Stage to Enrollment Flow
resource "authentik_flow_stage_binding" "enrollment_2_enrollment_mfa_setup" {
  target = authentik_flow.enrollment.uuid
  stage  = authentik_stage_authenticator_validate.enrollment_mfa_setup.id
  order  = 60
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = false
}

# Binds Login Stage to Enrollment Flow
resource "authentik_flow_stage_binding" "enrollment_2_enrollment_login" {
  target = authentik_flow.enrollment.uuid
  stage  = authentik_stage_user_login.enrollment_login.id
  order  = 70
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = true
}

# Binds Identification Stage to Recovery Flow
resource "authentik_flow_stage_binding" "recovery_2_recovery_identification" {
  target = authentik_flow.recovery.uuid
  stage  = authentik_stage_identification.recovery_identification.id
  order  = 10
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = true
}

# Binds Email Stage to Recovery Flow
resource "authentik_flow_stage_binding" "recovery_2_recovery_email" {
  target = authentik_flow.recovery.uuid
  stage  = authentik_stage_email.recovery_email.id
  order  = 20
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = true
}

# Binds MFA Validation Stage to Recovery Flow
resource "authentik_flow_stage_binding" "recovery_2_recovery_mfa_validation" {
  target = authentik_flow.recovery.uuid
  stage  = authentik_stage_authenticator_validate.recovery_mfa_validation.id
  order  = 30
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = false
}

# Binds Prompt Stage to Recovery Flow
resource "authentik_flow_stage_binding" "recovery_2_recovery_prompt" {
  target = authentik_flow.recovery.uuid
  stage  = authentik_stage_prompt.recovery_prompt.id
  order  = 40
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = true
}

# Binds User Write Stage to Recovery Flow
resource "authentik_flow_stage_binding" "recovery_2_recovery_write" {
  target = authentik_flow.recovery.uuid
  stage  = authentik_stage_user_write.recovery_write.id
  order  = 50
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = true
}

# Binds Login Stage to Recovery Flow
resource "authentik_flow_stage_binding" "recovery_2_recovery_login" {
  target = authentik_flow.recovery.uuid
  stage  = authentik_stage_user_login.recovery_login.id
  order  = 60
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = true
}

# Binds Identification Stage to Auth Flow
resource "authentik_flow_stage_binding" "auth_2_auth_identification" {
  target = authentik_flow.auth.uuid
  stage  = authentik_stage_identification.auth_identification.id
  order  = 10
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = false
}

# Binds MFA Validation Stage to Auth Flow
resource "authentik_flow_stage_binding" "auth_2_auth_mfa_validate" {
  target = authentik_flow.auth.uuid
  stage  = authentik_stage_authenticator_validate.auth_mfa_validate.id
  order  = 20
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = false
}

# Binds Login Stage to Auth Flow
resource "authentik_flow_stage_binding" "auth_2_auth_login" {
  target = authentik_flow.auth.uuid
  stage  = authentik_stage_user_login.auth_login.id
  order  = 30
  invalid_response_action = "retry"
  policy_engine_mode = "any"
  re_evaluate_policies = true
  evaluate_on_plan = false
}

# Binds Logout Stage to Logout Flow
resource "authentik_flow_stage_binding" "logout_2_logout" {
  target = authentik_flow.logout.uuid
  stage  = authentik_stage_user_logout.logout.id
  order  = 0
  invalid_response_action = "retry"
  policy_engine_mode = "all"
  re_evaluate_policies = true
  evaluate_on_plan = true
}

#
########################
#
# Add Policy Bindings
#
########################
#

# Binds Login Redirect Policy to enrollment_2_enrollment_login binding
resource "authentik_policy_binding" "enrollment_login_redirect_2_enrollment" {
  target = authentik_flow_stage_binding.enrollment_2_enrollment_login.id
  policy = authentik_policy_expression.enrollment_login_redirect.id
  order  = 0
  enabled = true
  negate = false
  timeout = 30
}

# Binds Check Username Policy to enrollment_2_enrollment_cancel
resource "authentik_policy_binding" "enrollment_check_username_2_enrollment" {
  target = authentik_flow_stage_binding.enrollment_2_enrollment_cancel.id
  policy = authentik_policy_expression.enrollment_check_username.id
  order  = 10
  enabled = true
  negate = true
  timeout = 30
}

# Binds Map Attributes Policy to enrollment_2_enrollment_cancel
resource "authentik_policy_binding" "enrollment_map_attributes_2_enrollment" {
  target = authentik_flow_stage_binding.enrollment_2_enrollment_cancel.id
  policy = authentik_policy_expression.enrollment_map_attributes.id
  order  = 20
  enabled = true
  negate = true
  timeout = 30
}

# Binds Redirect-If-Restored Policy to recovery_2_recovery_identification
resource "authentik_policy_binding" "recovery_skip_if_restored_2_recovery" {
  target = authentik_flow_stage_binding.recovery_2_recovery_identification.id
  policy = authentik_policy_expression.recovery_skip_if_restored.id
  order  = 0
  enabled = true
  negate = false
  timeout = 30
}

# Binds Set-Redirect-Url Policy to logout_2_logout
resource "authentik_policy_binding" "logout_set_redirect_url_2_logout" {
  target = authentik_flow_stage_binding.logout_2_logout.id
  policy = authentik_policy_expression.logout_set_redirect_url.id
  order  = 0
  enabled = true
  negate = false
  timeout = 30
}

# Binds Redirect-If-Unauth Policy to logout_2_logout
resource "authentik_policy_binding" "logout_redirect_if_unauth_2_logout" {
  target = authentik_flow_stage_binding.logout_2_logout.id
  policy = authentik_policy_expression.logout_redirect_if_unauth.id
  order  = 10
  enabled = true
  negate = false
  timeout = 30
}
