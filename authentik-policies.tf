#
########################
#
# Add Policies
#
########################
#

# Policy to set login redirect for jhaas as it gets lost in enrollment flow
# when user navigates away to confirm the email address
# resource "authentik_policy_expression" "enrollment_login_redirect" {
#   name              = "jhaas-enrollment-login-redirect"
#   execution_logging = true
#   expression        = <<-LOGIN_REDIRECT
#       context['flow_plan'].context['redirect'] = "${local.authentik_jhaas_login_redirect}"
#       return True
#   LOGIN_REDIRECT
# }

# Policy to immediatly force redirect home
resource "authentik_policy_expression" "force_home_redirect" {
  name              = "jhaas-force-home-redirect"
  execution_logging = true
  expression        = <<-FORCE_HOME_REDIRECT
      plan = request.context.get("flow_plan")
      if not plan:
        return False

      plan.redirect("/")
      return False
  FORCE_HOME_REDIRECT
}

# Policy to immediatly force login redirect for jhaas
resource "authentik_policy_expression" "enrollment_force_login_redirect" {
  name              = "jhaas-enrollment-force-login-redirect"
  execution_logging = true
  expression        = <<-FORCE_LOGIN_REDIRECT
      plan = request.context.get("flow_plan")
      if not plan:
        return False

      plan.redirect("${local.authentik_jhaas_login_redirect}")
      return False
  FORCE_LOGIN_REDIRECT
}

# Policy to check if TOS is accepted
resource "authentik_policy_expression" "enrollment_check_tos" {
  name              = "jhaas-enrollment-check-tos"
  execution_logging = true
  expression        = <<-CHECK_TOS
      check_tos = request.context.get("prompt_data").get("tos_accept")

      if not check_tos:
        ak_message("Please accept the terms of service to continue.")
        return False

      return True
  CHECK_TOS
}

# Policy to check if Info about Loss of Recovery Codes is accepted
resource "authentik_policy_expression" "check_recovery_codes_warning_accept" {
  name              = "jhaas-check-recovery-codes-warning-accept"
  execution_logging = true
  expression        = <<-CHECK_RECOVERY_CODES_WARNING_ACCEPT
      check_recovery_codes_accept = request.context.get("prompt_data").get("recovery_codes_accept")

      if not check_recovery_codes_accept:
        ak_message("Please confirm that you understand the consequences of losing your recovery codes.")
        return False

      return True
  CHECK_RECOVERY_CODES_WARNING_ACCEPT
}

# Policy to drop all MFA devices
resource "authentik_policy_expression" "drop_mfa_devices" {
  name              = "jhaas-drop-mfa-devices"
  execution_logging = true
  expression        = <<-DROP_MFA_DEVICES
      from authentik.stages.authenticator import devices_for_user

      try:
        for device in devices_for_user(request.user):
          device_class = device.__class__.__name__.lower().replace("device", "")
          ak_logger.info("next delete: {device_class}.".format(device_class=device_class))
          device.delete()
          ak_logger.info("deleted: {device_class}.".format(device_class=device_class))
        return True
      except Exception as e:
        ak_logger.warning(str(e))

      ak_message('Something went wrong. Please contact administrator.')
      return False
  DROP_MFA_DEVICES
}

# Policy to drop Recovery Codes
resource "authentik_policy_expression" "drop_recovery_codes" {
  name              = "jhaas-drop-recovery-codes"
  execution_logging = true
  expression        = <<-DROP_RECOVERY_CODES
      from authentik.stages.authenticator import devices_for_user

      try:
        for device in devices_for_user(request.user):
          device_class = device.__class__.__name__.lower().replace("device", "")
          if device_class == 'static':
            ak_logger.info("next delete: {device_class}.".format(device_class=device_class))
            device.delete()
            ak_logger.info("deleted: {device_class}.".format(device_class=device_class))
        return True
      except Exception as e:
        ak_logger.warning(str(e))

      ak_message('Something went wrong. Please contact administrator.')
      return False
  DROP_RECOVERY_CODES
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

# Policy to check mail domain validity
resource "authentik_policy_expression" "enrollment_check_mail_domain" {
  name              = "jhaas-enrollment-check-mail-domain"
  execution_logging = true
  expression        = <<-CHECK_MAIL_DOMAIN
      dns = __import__('dns.resolver')

      email = context['prompt_data']['email']
      domain = email.split('@')[1]

      try:
        records = dns.resolver.query(domain, 'MX')
        if records and records[0].exchange:
          return True
      except:
        pass

      ak_message((
        'Oops - something seems to be wrong with your email address!'
        '\n'
        'Could not find Mail Server for Domain: {domain}'
      ).format(domain=domain))

      return False
  CHECK_MAIL_DOMAIN
}

# Check password policy
resource "authentik_policy_password" "global_check_password" {
  name              = "jhaas-global-check-password"
  execution_logging = true

  password_field = "password"
  length_min     = 12
  error_message  = "The password must be at least 12 characters long."

  amount_digits    = 0
  amount_lowercase = 0
  amount_symbols   = 0
  amount_uppercase = 0

  check_have_i_been_pwned = false
  check_static_rules      = true
  check_zxcvbn            = true
  zxcvbn_score_threshold  = 2
}

# # Policy to check if this is a restored session
# resource "authentik_policy_expression" "recovery_skip_if_restored" {
#   name              = "jhaas-recovery-skip-if-restored"
#   execution_logging = true
#   expression        = <<-SKIP_IF_RESTORED
#       return bool(request.context.get('is_restored', True))
#   SKIP_IF_RESTORED
# }

# Policy to set redirect url
resource "authentik_policy_expression" "logout_set_redirect_url" {
  name              = "jhaas-logout-set-redirect-url"
  execution_logging = true
  expression        = <<-SET_REDIRECT_URL
      context['flow_plan'].context['redirect'] = "${local.authentik_jhaas_verify_redirect}"

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

      plan.redirect("${local.authentik_jhaas_verify_redirect}")
      return False
  REDIRECT_IF_UNAUTH
}

# Policy to check recovery codes presence
resource "authentik_policy_expression" "check_recovery_codes_presence" {
  name              = "jhaas-check-recovery-codes-presence"
  execution_logging = true
  expression        = <<-CHECK_RECOVERY_CODES_PRESENCE
      return ak_user_has_authenticator(request.user, 'static')
  CHECK_RECOVERY_CODES_PRESENCE
}
