#
########################
#
# Output IDs of configuration flows
#
########################
#
output "totp_configuration_id" {
  value = authentik_stage_authenticator_totp.totp_setup.id
}
output "webauthn_configuration_id" {
  value = authentik_stage_authenticator_webauthn.webauthn_setup.id
}
output "mfa_static_configuration_id" {
  value = authentik_stage_authenticator_static.mfa_static_setup.id
}
output "password_configuration_id" {
  value = authentik_stage_password.auth_password.id
}
