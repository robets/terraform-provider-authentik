resource "authentik_service_account" "automation" {
  username = "example-automation"
  name     = "Example automation"
  groups   = [authentik_group.automation.id]
  attributes = jsonencode({
    owner = "platform"
  })
  token_description = "Example automation app password"
}
