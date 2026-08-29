package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "goauthentik.io/api/v3"
)

func TestAccResourceServiceAccount(t *testing.T) {
	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceServiceAccount(rName, 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authentik_service_account.account", "username", rName),
					resource.TestCheckResourceAttrSet("authentik_service_account.account", "app_password"),
					resource.TestCheckResourceAttrSet("authentik_service_account.account", "token_identifier"),
				),
			},
			{
				Config: testAccResourceServiceAccount(rName, 2),
				Check: resource.TestCheckResourceAttr(
					"authentik_service_account.account", "app_password_version", "2",
				),
			},
		},
	})
}

func testAccResourceServiceAccount(name string, version int) string {
	return fmt.Sprintf(`
resource "authentik_service_account" "account" {
  username             = "%[1]s"
  name                 = "%[1]s"
  token_description    = "%[1]s"
  app_password_version = %[2]d
}
`, name, version)
}

const serviceAccountTestUser = `{
  "pk": 42,
  "username": "svc",
  "name": "Service account",
  "is_active": true,
  "date_joined": "2026-08-29T00:00:00Z",
  "is_superuser": false,
  "groups": ["group-1"],
  "groups_obj": [],
  "roles": [],
  "roles_obj": [],
  "email": "svc@example.com",
  "avatar": "",
  "attributes": {"owner":"platform"},
  "uid": "user-uid",
  "path": "goauthentik.io/service-accounts",
  "type": "service_account",
  "uuid": "00000000-0000-0000-0000-000000000042",
  "password_change_date": "2026-08-29T00:00:00Z",
  "last_updated": "2026-08-29T00:00:00Z"
}`

func serviceAccountTestToken() string {
	return fmt.Sprintf(`{
  "pk": "service-account-svc-password",
  "identifier": "service-account-svc-password",
  "intent": "app_password",
  "user": 42,
  "user_obj": %s,
  "description": "Managed app password",
  "expires": null,
  "expiring": false
}`, serviceAccountTestUser)
}

func TestResourceServiceAccountSchemaProtectsPassword(t *testing.T) {
	password := resourceServiceAccount().Schema["app_password"]
	assert.True(t, password.Computed)
	assert.True(t, password.Sensitive)
	assert.False(t, password.Optional)
	assert.False(t, password.WriteOnly)
}

func TestResourceServiceAccountCreate(t *testing.T) {
	var serviceAccountCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v3/core/users/service_account/":
			serviceAccountCalls++
			var body api.UserServiceAccountRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			assert.Equal(t, "svc", body.Name)
			assert.False(t, body.GetCreateGroup())
			assert.False(t, body.GetExpiring())
			_, _ = w.Write([]byte(`{
          "username":"svc",
          "token":"created-secret",
          "user_uid":"user-uid",
          "user_pk":42
        }`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/core/tokens/":
			assert.Equal(t, "svc", r.URL.Query().Get("user__username"))
			assert.Equal(t, "app_password", r.URL.Query().Get("intent"))
			_, _ = fmt.Fprintf(w, `{"pagination":{"next":0,"previous":0,"count":1,"current":1,"total_pages":1,"start_index":1,"end_index":1},"results":[%s],"autocomplete":{}}`, serviceAccountTestToken())
		case r.Method == http.MethodPut && r.URL.Path == "/api/v3/core/users/42/":
			body := map[string]any{}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			assert.Equal(t, "service_account", body["type"])
			assert.Equal(t, []any{"group-1"}, body["groups"])
			_, _ = w.Write([]byte(serviceAccountTestUser))
		case r.Method == http.MethodPut && r.URL.Path == "/api/v3/core/tokens/service-account-svc-password/":
			body := map[string]any{}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			assert.Equal(t, "app_password", body["intent"])
			assert.Equal(t, false, body["expiring"])
			_, _ = w.Write([]byte(serviceAccountTestToken()))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/core/users/42/":
			_, _ = w.Write([]byte(serviceAccountTestUser))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v3/core/tokens/service-account-svc-password/":
			_, _ = w.Write([]byte(serviceAccountTestToken()))
		default:
			http.Error(w, r.Method+" "+r.URL.String(), http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	config := api.NewConfiguration()
	config.Debug = false
	config.Servers = api.ServerConfigurations{{URL: server.URL + "/api/v3"}}
	client := &APIClient{client: api.NewAPIClient(config)}
	d := schema.TestResourceDataRaw(t, resourceServiceAccount().Schema, map[string]any{
		"username":          "svc",
		"name":              "Service account",
		"email":             "svc@example.com",
		"groups":            []any{"group-1"},
		"attributes":        `{"owner":"platform"}`,
		"token_description": "Managed app password",
	})

	diags := resourceServiceAccountCreate(t.Context(), d, client)

	require.False(t, diags.HasError(), diags)
	assert.Equal(t, 1, serviceAccountCalls)
	assert.Equal(t, "42", d.Id())
	assert.Equal(t, "created-secret", d.Get("app_password"))
	assert.Equal(t, "service-account-svc-password", d.Get("token_identifier"))
}

func TestGenerateServiceAccountPassword(t *testing.T) {
	first, err := generateServiceAccountPassword()
	require.NoError(t, err)
	second, err := generateServiceAccountPassword()
	require.NoError(t, err)
	assert.Len(t, first, 64)
	assert.NotEqual(t, first, second)
	assert.False(t, strings.ContainsAny(first, "+/="))
}

func TestServiceAccountSetPassword(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v3/core/tokens/service-account-svc-password/set_key/", r.URL.Path)
		var body api.TokenSetKeyRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "rotated-secret", body.Key)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	config := api.NewConfiguration()
	config.Debug = false
	config.Servers = api.ServerConfigurations{{URL: server.URL + "/api/v3"}}
	client := &APIClient{client: api.NewAPIClient(config)}
	d := schema.TestResourceDataRaw(t, resourceServiceAccount().Schema, map[string]any{
		"username":         "svc",
		"name":             "Service account",
		"token_identifier": "service-account-svc-password",
	})
	d.SetId("42")

	diags := serviceAccountSetPassword(t.Context(), d, client, "rotated-secret")

	require.False(t, diags.HasError(), diags)
}
