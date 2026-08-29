package provider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	api "goauthentik.io/api/v3"
	"goauthentik.io/terraform-provider-authentik/pkg/helpers"
)

func resourceServiceAccount() *schema.Resource {
	return &schema.Resource{
		Description: "Directory --- Creates a service account and its non-expiring app password atomically. " +
			"The password is returned once by authentik and retained as sensitive Terraform state; import is therefore unsupported. " +
			"Changing app_password_version rotates the password through set_key without reading its current value. " +
			"The caller needs add_user and add_token plus Initial Permissions for future user and token management, including set_token_key but not view_token_key.",
		CreateContext: resourceServiceAccountCreate,
		ReadContext:   resourceServiceAccountRead,
		UpdateContext: resourceServiceAccountUpdate,
		DeleteContext: resourceServiceAccountDelete,
		Importer: &schema.ResourceImporter{
			StateContext: func(context.Context, *schema.ResourceData, any) ([]*schema.ResourceData, error) {
				return nil, fmt.Errorf("authentik_service_account cannot be imported because authentik returns its app password only at creation")
			},
		},
		Schema: map[string]*schema.Schema{
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Service account username.",
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Service account display name.",
			},
			"email": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Service account email address.",
			},
			"path": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "goauthentik.io/service-accounts",
				Description: "Service account path.",
			},
			"is_active": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Whether the service account is active.",
			},
			"groups": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Group UUIDs assigned to the service account.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"attributes": {
				Type:             schema.TypeString,
				Optional:         true,
				Default:          "{}",
				Description:      helpers.JSONDescription,
				DiffSuppressFunc: helpers.DiffSuppressJSON,
				ValidateDiagFunc: helpers.ValidateJSON,
			},
			"token_description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the app-password token.",
			},
			"app_password": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "App password returned once by authentik and retained in Terraform state.",
			},
			"app_password_version": {
				Type:         schema.TypeInt,
				Optional:     true,
				Default:      1,
				ValidateFunc: validation.IntAtLeast(1),
				Description:  "Change this value to generate and set a new app password.",
			},
			"token_identifier": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Identifier of the app-password token created by authentik.",
			},
		},
	}
}

func serviceAccountUserModel(d *schema.ResourceData) (*api.UserRequest, diag.Diagnostics) {
	attributes, diags := helpers.GetJSON[map[string]any](d, "attributes")
	if diags != nil {
		return nil, diags
	}
	return &api.UserRequest{
		Username:   d.Get("username").(string),
		Name:       d.Get("name").(string),
		Type:       api.USERTYPEENUM_SERVICE_ACCOUNT.Ptr(),
		IsActive:   new(d.Get("is_active").(bool)),
		Path:       new(d.Get("path").(string)),
		Email:      helpers.GetP[string](d, "email"),
		Groups:     helpers.CastSlice[string](d, "groups"),
		Roles:      []string{},
		Attributes: attributes,
	}, nil
}

func serviceAccountTokenModel(d *schema.ResourceData, userID int32, identifier string) api.TokenRequest {
	return api.TokenRequest{
		Identifier:  identifier,
		User:        new(userID),
		Intent:      new(api.INTENTENUM_APP_PASSWORD),
		Description: helpers.GetP[string](d, "token_description"),
		Expiring:    new(false),
	}
}

func serviceAccountFindToken(ctx context.Context, c *APIClient, username string, userID int32) (*api.Token, *http.Response, error) {
	intent := api.INTENTENUM_APP_PASSWORD
	tokens, hr, err := c.client.CoreAPI.CoreTokensList(ctx).
		UserUsername(username).
		Intent(intent).
		PageSize(100).
		Execute()
	if err != nil {
		return nil, hr, err
	}
	var match *api.Token
	for i := range tokens.Results {
		token := &tokens.Results[i]
		if token.User != nil && *token.User == userID && token.Intent != nil && *token.Intent == intent {
			if match != nil {
				return nil, hr, fmt.Errorf("multiple app-password tokens found for service account %q", username)
			}
			match = token
		}
	}
	if match == nil {
		return nil, hr, fmt.Errorf("authentik did not return the app-password token created for service account %q", username)
	}
	return match, hr, nil
}

func serviceAccountUpdateObjects(ctx context.Context, d *schema.ResourceData, c *APIClient) diag.Diagnostics {
	userID, err := strconv.ParseInt(d.Id(), 10, 32)
	if err != nil {
		return diag.FromErr(err)
	}
	user, diags := serviceAccountUserModel(d)
	if diags != nil {
		return diags
	}
	_, hr, err := c.client.CoreAPI.CoreUsersUpdate(ctx, int32(userID)).UserRequest(*user).Execute()
	if err != nil {
		return helpers.HTTPToDiag(d, hr, err)
	}
	tokenIdentifier := d.Get("token_identifier").(string)
	token := serviceAccountTokenModel(d, int32(userID), tokenIdentifier)
	_, hr, err = c.client.CoreAPI.CoreTokensUpdate(ctx, tokenIdentifier).TokenRequest(token).Execute()
	if err != nil {
		return helpers.HTTPToDiag(d, hr, err)
	}
	return nil
}

func resourceServiceAccountCreate(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	c := m.(*APIClient)
	request := api.NewUserServiceAccountRequest(d.Get("username").(string))
	request.SetCreateGroup(false)
	request.SetExpiring(false)
	created, hr, err := c.client.CoreAPI.CoreUsersServiceAccountCreate(ctx).
		UserServiceAccountRequest(*request).
		Execute()
	if err != nil {
		return helpers.HTTPToDiag(d, hr, err)
	}
	if created.Username != d.Get("username").(string) || created.UserPk <= 0 || created.Token == "" {
		return diag.Errorf("authentik returned an incomplete service-account response")
	}

	d.SetId(strconv.Itoa(int(created.UserPk)))
	if err := d.Set("app_password", created.Token); err != nil {
		return diag.FromErr(err)
	}
	token, hr, err := serviceAccountFindToken(ctx, c, created.Username, created.UserPk)
	if err != nil {
		if hr != nil && hr.StatusCode >= 400 {
			return helpers.HTTPToDiag(d, hr, err)
		}
		return diag.FromErr(err)
	}
	if err := d.Set("token_identifier", token.Identifier); err != nil {
		return diag.FromErr(err)
	}
	if diags := serviceAccountUpdateObjects(ctx, d, c); diags.HasError() {
		return diags
	}
	return resourceServiceAccountRead(ctx, d, m)
}

func resourceServiceAccountRead(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	c := m.(*APIClient)
	if password, ok := d.GetOk("app_password"); !ok || password.(string) == "" {
		return diag.Errorf("service account state has no app password and authentik cannot return it again")
	}
	userID, err := strconv.ParseInt(d.Id(), 10, 32)
	if err != nil {
		return diag.FromErr(err)
	}
	user, hr, err := c.client.CoreAPI.CoreUsersRetrieve(ctx, int32(userID)).Execute()
	if err != nil {
		if hr != nil && hr.StatusCode == http.StatusNotFound {
			return diag.Errorf("service account %d is missing or inaccessible; refusing to discard its unrecoverable app password", userID)
		}
		return helpers.HTTPToDiag(d, hr, err)
	}
	if user.Type == nil || *user.Type != api.USERTYPEENUM_SERVICE_ACCOUNT {
		return diag.Errorf("authentik user %d is not a service account", userID)
	}

	tokenIdentifier := d.Get("token_identifier").(string)
	if tokenIdentifier == "" {
		return diag.Errorf("service account state has no token identifier; the app password cannot be recovered")
	}
	token, hr, err := c.client.CoreAPI.CoreTokensRetrieve(ctx, tokenIdentifier).Execute()
	if err != nil {
		if hr != nil && hr.StatusCode == http.StatusNotFound {
			return diag.Errorf("app-password token %q is missing; refusing to recreate an unrecoverable secret", tokenIdentifier)
		}
		return helpers.HTTPToDiag(d, hr, err)
	}
	if token.User == nil || *token.User != int32(userID) || token.Intent == nil || *token.Intent != api.INTENTENUM_APP_PASSWORD {
		return diag.Errorf("token %q is not the app password owned by service account %d", tokenIdentifier, userID)
	}
	if token.Expiring == nil || *token.Expiring {
		return diag.Errorf("app-password token %q is unexpectedly expiring", tokenIdentifier)
	}

	helpers.SetWrapper(d, "username", user.Username)
	helpers.SetWrapper(d, "name", user.Name)
	helpers.SetWrapper(d, "email", user.Email)
	helpers.SetWrapper(d, "is_active", user.IsActive)
	helpers.SetWrapper(d, "path", user.Path)
	helpers.SetWrapper(d, "groups", helpers.ListConsistentMerge(
		helpers.CastSlice[string](d, "groups"), user.Groups,
	))
	if diags := helpers.SetJSON(d, "attributes", user.Attributes); diags != nil {
		return diags
	}
	helpers.SetWrapper(d, "token_description", token.Description)
	helpers.SetWrapper(d, "token_identifier", token.Identifier)
	return nil
}

func generateServiceAccountPassword() (string, error) {
	value := make([]byte, 48)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func serviceAccountSetPassword(ctx context.Context, d *schema.ResourceData, c *APIClient, password string) diag.Diagnostics {
	tokenIdentifier := d.Get("token_identifier").(string)
	hr, err := c.client.CoreAPI.CoreTokensSetKeyCreate(ctx, tokenIdentifier).
		TokenSetKeyRequest(*api.NewTokenSetKeyRequest(password)).
		Execute()
	if err != nil {
		return helpers.HTTPToDiag(d, hr, err)
	}
	return nil
}

func resourceServiceAccountUpdate(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	c := m.(*APIClient)
	if diags := serviceAccountUpdateObjects(ctx, d, c); diags.HasError() {
		return diags
	}
	if d.HasChange("app_password_version") {
		password, err := generateServiceAccountPassword()
		if err != nil {
			return diag.FromErr(err)
		}
		if diags := serviceAccountSetPassword(ctx, d, c, password); diags.HasError() {
			return diags
		}
		if err := d.Set("app_password", password); err != nil {
			return diag.FromErr(err)
		}
	}
	return resourceServiceAccountRead(ctx, d, m)
}

func resourceServiceAccountDelete(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	c := m.(*APIClient)
	userID, err := strconv.ParseInt(d.Id(), 10, 32)
	if err != nil {
		return diag.FromErr(err)
	}
	tokenIdentifier := d.Get("token_identifier").(string)
	if tokenIdentifier != "" {
		hr, err := c.client.CoreAPI.CoreTokensDestroy(ctx, tokenIdentifier).Execute()
		if err != nil && (hr == nil || hr.StatusCode != http.StatusNotFound) {
			return helpers.HTTPToDiag(d, hr, err)
		}
	}
	hr, err := c.client.CoreAPI.CoreUsersDestroy(ctx, int32(userID)).Execute()
	if err != nil && (hr == nil || hr.StatusCode != http.StatusNotFound) {
		return helpers.HTTPToDiag(d, hr, err)
	}
	d.SetId("")
	return nil
}
