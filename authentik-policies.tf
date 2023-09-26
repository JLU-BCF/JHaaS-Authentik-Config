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

# Check password policy
resource "authentik_policy_password" "global_check_password" {
  name = "jhaas-global-check-password"
  execution_logging = true

  password_field = "password"
  length_min  = 12
  error_message = "The password must be at least 12 characters long."

  amount_digits       = 0
  amount_lowercase    = 0
  amount_symbols      = 0
  amount_uppercase    = 0

  check_have_i_been_pwned = false
  check_static_rules      = true
  check_zxcvbn            = true
  zxcvbn_score_threshold  = 2
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
