package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "goauthentik.io/api/v3"
)

func TestAccResourceToken(t *testing.T) {
	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	expires := time.Now().Add(30 * time.Minute).Format(time.RFC3339)
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceToken(rName, expires),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authentik_token.token", "identifier", rName),
					resource.TestCheckResourceAttrSet("authentik_token.token", "key"),
				),
			},
		},
	})
}

func TestAccResourceTokenWriteOnlyKey(t *testing.T) {
	rName := acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	expires := time.Now().Add(30 * time.Minute).Format(time.RFC3339)
	resource.UnitTest(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceTokenWriteOnlyKey(rName, expires, "first-secret", 1),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authentik_token.token", "key_wo_version", "1"),
					resource.TestCheckNoResourceAttr("authentik_token.token", "key_wo"),
				),
			},
			{
				Config: testAccResourceTokenWriteOnlyKey(rName, expires, "second-secret", 2),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("authentik_token.token", "key_wo_version", "2"),
					resource.TestCheckNoResourceAttr("authentik_token.token", "key_wo"),
				),
			},
		},
	})
}

func TestResourceTokenSetKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v3/core/tokens/token-1/set_key/", r.URL.Path)

		var body api.TokenSetKeyRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "secret-value", body.Key)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	config := api.NewConfiguration()
	config.Servers = api.ServerConfigurations{{URL: server.URL + "/api/v3"}}
	client := &APIClient{client: api.NewAPIClient(config)}
	d := schema.TestResourceDataRaw(t, resourceToken().Schema, nil)
	d.SetId("token-1")

	diags := resourceTokenSetKey(t.Context(), d, client, "secret-value")

	require.False(t, diags.HasError(), diags)
}

func testAccResourceToken(name string, time string) string {
	return fmt.Sprintf(`
resource "authentik_user" "name" {
	username = "%[1]s"
	name = "%[1]s"
}

resource "authentik_token" "token" {
	user = authentik_user.name.id
	identifier = "%[1]s"
	expires = "%[2]s"
	description = "%[1]s"
	retrieve_key = true
}
`, name, time)
}

func testAccResourceTokenWriteOnlyKey(name string, expires string, key string, version int) string {
	return fmt.Sprintf(`
resource "authentik_user" "name" {
	username = "%[1]s"
	name = "%[1]s"
}

resource "authentik_token" "token" {
	user = authentik_user.name.id
	identifier = "%[1]s"
	expires = "%[2]s"
	description = "%[1]s"
	key_wo = "%[3]s"
	key_wo_version = %[4]d
}
`, name, expires, key, version)
}
