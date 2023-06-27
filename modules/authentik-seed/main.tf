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
