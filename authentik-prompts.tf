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
  name      = "jhaas-enrollment-tos-text"
  label     = "Terms of service"
  field_key = "tos_text"
  type      = "static"
  order     = 0
  required  = true

  sub_text = <<-TOS_TEXT
      You are about to create an account for JHaaS. This is a prototype and
      we do not assume any liability or warranty for anything. Your data will not
      be shared with any third party and will be completely removed once the prototype
      stage is over. Read the <a target="_blank" href="${local.authentik_tos_url}">terms
      of use.</a>
  TOS_TEXT
}

# Setup TOS acceptance field for enrollment
resource "authentik_stage_prompt_field" "enrollment_tos_accept" {
  name      = "jhaas-enrollment-tos-accept"
  label     = "I accept the terms of service"
  field_key = "tos_accept"
  type      = "checkbox"
  order     = 5
  required  = true
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
  name      = "jhaas-enrollment-revocery-codes-text"
  label     = "Information about recovery codes"
  field_key = "revocery_codes_text"
  type      = "static"
  order     = 0
  required  = true

  sub_text = <<-TOKEN_TEXT
      The next step is to set up multi-factor authentication. First, static
      recovery tokens are generated for you. It is important to keep these tokens
      safe (e.g. print them out) to be able to reset the account in case a second
      factor is lost.
  TOKEN_TEXT
}

# Setup Pre MFA Setup Text field for enrollment
resource "authentik_stage_prompt_field" "enrollment_mfa_text" {
  name      = "jhaas-enrollment-mfa-text"
  label     = "Information about MFA"
  field_key = "mfa_text"
  type      = "static"
  order     = 0
  required  = true

  sub_text = <<-MFA_TEXT
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
