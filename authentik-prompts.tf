#
########################
#
# Add Prompts
#
########################
#

# Setup common back-to-login text field
resource "authentik_stage_prompt_field" "back_to_login" {
  name      = "jhaas-back-to-login"
  label     = "Back to login"
  field_key = "back_to_login"
  type      = "static"
  order     = 1000
  required  = true

  sub_text = "&lt; back to <a href=\"/\">login</a>"
}

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
  name      = "jhaas-enrollment-tos-text"
  label     = "Terms of service"
  field_key = "tos_text"
  type      = "static"
  order     = 0
  required  = true

  initial_value = <<-TOS_TEXT
      You are about to create an account for JHaaS. This is currently in the evaluation phase and
      we do not assume any liability or warranty for anything. Your data will not
      be shared with any third party and will be completely removed once the evaluation phase
      is over. Read the <a target="_blank" onclick="window.open(this.href, '_blank', 'resizable=yes,height=600,width=460'); return false;" href="${local.authentik_tos_url}">terms
      of service and privacy policy.</a>
  TOS_TEXT
}

# Setup TOS acceptance field for enrollment
resource "authentik_stage_prompt_field" "enrollment_tos_accept" {
  name      = "jhaas-enrollment-tos-accept"
  label     = "I accept the terms of service and privacy policy"
  field_key = "tos_accept"
  type      = "checkbox"
  order     = 5

  # presence will be checked through policy
  required = false
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
  name      = "jhaas-enrollment-recovery-codes-text"
  label     = "Information about recovery codes"
  field_key = "recovery_codes_text"
  type      = "static"
  order     = 0
  required  = true

  initial_value = <<-TOKEN_TEXT
      The next step is to set up multi-factor authentication. First, static
      recovery tokens are generated for you. It is important to keep these tokens
      safe (e.g. print them out) to be able to reset the account in case a second
      factor is lost.
  TOKEN_TEXT
}

# Setup Info about Loss of Recovery Codes acceptance field for enrollment
resource "authentik_stage_prompt_field" "recovery_codes_warning_accept" {
  name      = "jhaas-recovery-codes-warning-accept"
  label     = "I understand that the loss of these recovery tokens may result in a permanent lockout from my account"
  field_key = "recovery_codes_accept"
  type      = "checkbox"
  order     = 5

  # presence will be checked through policy
  required = false
}

# Setup Pre MFA Setup Text field for enrollment
resource "authentik_stage_prompt_field" "enrollment_mfa_text" {
  name      = "jhaas-enrollment-mfa-text"
  label     = "Information about MFA"
  field_key = "mfa_text"
  type      = "static"
  order     = 0
  required  = true

  initial_value = <<-MFA_TEXT
      In the next step, you select a second factor. This can be done either
      with an Authenticator app (a QR code will be displayed which has to be scanned
      with the Authenticator app) or with a WebAuthn device such as a Yubikey.
  MFA_TEXT
}

# Setup Redirect Text field for enrollment
resource "authentik_stage_prompt_field" "enrollment_redirect_info" {
  name      = "jhaas-enrollment-redirect-info"
  label     = "Redirect Info"
  field_key = "redirect_info"
  type      = "static"
  order     = 0
  required  = true

  initial_value = <<-MFA_TEXT
      Registration completed. You will now be redirected.
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

# Setup Text field for mfa recovery not applicable
resource "authentik_stage_prompt_field" "mfa_recovery_not_applicable" {
  name      = "jhaas-mfa-recovery-not-applicable"
  label     = "MFA Recovery not applicable"
  field_key = "mfa_recovery_not_applicable"
  type      = "static"
  order     = 0
  required  = true

  initial_value = <<-MFA_RECOVERY_NOT_APPLICABLE_TEXT
      <p style="color: #FF0000; font-size: 4em; text-align: center;">&#x26A0;</p>
      <p style="margin-bottom: 1em;">
        There are no recovery codes stored in your account. It is therefore not
        possible to reset multi factor authentication for your account. Please
        contact an administrator.
      </p>
      <p style="text-align: center;">
        <a href="/">Back to Login</a>
      </p>
  MFA_RECOVERY_NOT_APPLICABLE_TEXT
}

# Setup Text field for mfa recovery
resource "authentik_stage_prompt_field" "mfa_recovery_reset_text" {
  name      = "jhaas-mfa-recovery-reset-text"
  label     = "Information about MFA recovery"
  field_key = "mfa_recovery_reset_text"
  type      = "static"
  order     = 0
  required  = true

  initial_value = <<-MFA_RESET_TEXT
      In the next step, your stored MFA devices will be deleted. Your current
      recovery codes will become invalid and you will receive a new set of
      recovery codes. You must then register a new second factor.
  MFA_RESET_TEXT
}

# Setup Text field for mfa recovery success
resource "authentik_stage_prompt_field" "mfa_recovery_success" {
  name      = "jhaas-mfa-recovery-success"
  label     = "MFA Reset successfull"
  field_key = "mfa_recovery_success"
  type      = "static"
  order     = 0
  required  = true

  initial_value = <<-MFA_RECOVERY_SUCCESS
      You have successfully reset your second factor.
      You may now log in as usual.
  MFA_RECOVERY_SUCCESS
}

# Setup Text field for recovery codes missing
resource "authentik_stage_prompt_field" "recovery_codes_missing" {
  name      = "jhaas-recovery-codes-missing"
  label     = "Recovery Codes Missing"
  field_key = "recovery_codes_missing"
  type      = "static"
  order     = 0
  required  = true

  initial_value = <<-RECOVERY_CODES_MISSING
      There are no recovery codes stored in your account. You need recovery codes
      to reset your second factor if necessary. Recovery codes for your account will
      be generated in the next step.
  RECOVERY_CODES_MISSING
}

# Setup Text field for recovery codes exist when trying to create new
resource "authentik_stage_prompt_field" "recovery_codes_existing" {
  name      = "jhaas-recovery-codes-existing"
  label     = "Recovery Codes Existing"
  field_key = "recovery_codes_existing"
  type      = "static"
  order     = 0
  required  = true

  initial_value = <<-RECOVERY_CODES_EXISTING
      Recovery tokens are already stored in your account. Please note that when new
      recovery tokens are created, the old ones become invalid.
  RECOVERY_CODES_EXISTING
}
