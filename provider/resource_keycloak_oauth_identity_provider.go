package provider

import (
	"errors"

	"dario.cat/mergo"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/keycloak/terraform-provider-keycloak/keycloak"
	"github.com/keycloak/terraform-provider-keycloak/keycloak/types"
)

func resourceKeycloakOauthIdentityProvider() *schema.Resource {
	oauthSchema := map[string]*schema.Schema{
		"provider_id": {
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "oauth2",
			Description: "provider id, is always oauth2, unless you have a custom implementation",
		},
		"display_name": {
			Type:        schema.TypeString,
			Optional:    true,
			Computed:    true,
			Description: "The human-friendly name of the identity provider, used in the log in form.",
		},
		"authorization_url": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "OAuth authorization URL.",
		},
		"client_id": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Client ID.",
		},
		"client_secret": {
			Type:          schema.TypeString,
			Optional:      true,
			Sensitive:     true,
			Description:   "Client Secret.",
			ConflictsWith: []string{"client_secret_wo", "client_secret_wo_version"},
		},
		"client_secret_wo": {
			Type:          schema.TypeString,
			Optional:      true,
			Sensitive:     true,
			WriteOnly:     true,
			ConflictsWith: []string{"client_secret"},
			RequiredWith:  []string{"client_secret_wo_version"},
			Description:   "Client Secret as write-only argument",
		},
		"client_secret_wo_version": {
			Type:          schema.TypeInt,
			Optional:      true,
			ConflictsWith: []string{"client_secret"},
			RequiredWith:  []string{"client_secret_wo"},
			Description:   "Version of the Client secret write-only argument",
		},
		"user_info_url": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "User Info URL.",
		},
		"hide_on_login_page": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "Hide On Login Page.",
		},
		"token_url": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Token URL.",
		},
		"login_hint": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Login Hint.",
		},
		"ui_locales": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "Pass current locale to identity provider",
		},
		"default_scopes": {
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "",
			Description: "The scopes to be sent when asking for authorization. It can be a space-separated list of scopes.",
		},
	}

	oauthResource := resourceKeycloakIdentityProvider()
	oauthResource.Schema = mergeSchemas(oauthResource.Schema, oauthSchema)
	oauthResource.CreateContext = resourceKeycloakIdentityProviderCreate(getOauthIdentityProviderFromData, setOauthIdentityProviderData)
	oauthResource.ReadContext = resourceKeycloakIdentityProviderRead(setOauthIdentityProviderData)
	oauthResource.UpdateContext = resourceKeycloakIdentityProviderUpdate(getOauthIdentityProviderFromData, setOauthIdentityProviderData)
	oauthResource.ValidateRawResourceConfigFuncs = []schema.ValidateRawResourceConfigFunc{
		requiredWithoutAll(cty.GetAttrPath("client_secret"), []cty.Path{cty.GetAttrPath("client_secret_wo"), cty.GetAttrPath("client_secret_wo_version")}),
	}

	return oauthResource
}

func getOauthIdentityProviderFromData(data *schema.ResourceData, keycloakVersion *version.Version) (*keycloak.IdentityProvider, error) {
	rec, defaultConfig := getIdentityProviderFromData(data, keycloakVersion)
	rec.ProviderId = data.Get("provider_id").(string)

	oauthIdentityProviderConfig := &keycloak.IdentityProviderConfig{
		AuthorizationUrl: data.Get("authorization_url").(string),
		ClientId:         data.Get("client_id").(string),
		ClientSecret:     data.Get("client_secret").(string),
		TokenUrl:         data.Get("token_url").(string),
		UILocales:        types.KeycloakBoolQuoted(data.Get("ui_locales").(bool)),
		LoginHint:        data.Get("login_hint").(string),
		UserInfoUrl:      data.Get("user_info_url").(string),
		DefaultScope:     data.Get("default_scopes").(string),
	}

	if data.Get("client_secret_wo_version").(int) != 0 && data.HasChange("client_secret_wo_version") {
		clientSecretWriteOnly, clientSecretWriteOnlyDiags := data.GetRawConfigAt(cty.GetAttrPath("client_secret_wo"))
		if clientSecretWriteOnlyDiags.HasError() {
			return nil, errors.New("error reading 'client_secret_wo' argument")
		}

		oauthIdentityProviderConfig.ClientSecret = clientSecretWriteOnly.AsString()
	}

	if err := mergo.Merge(oauthIdentityProviderConfig, defaultConfig); err != nil {
		return nil, err
	}

	rec.Config = oauthIdentityProviderConfig

	return rec, nil
}

func setOauthIdentityProviderData(data *schema.ResourceData, identityProvider *keycloak.IdentityProvider, keycloakVersion *version.Version) error {
	setIdentityProviderData(data, identityProvider, keycloakVersion)
	data.Set("provider_id", identityProvider.ProviderId)
	data.Set("authorization_url", identityProvider.Config.AuthorizationUrl)
	data.Set("client_id", identityProvider.Config.ClientId)
	data.Set("user_info_url", identityProvider.Config.UserInfoUrl)
	data.Set("token_url", identityProvider.Config.TokenUrl)
	data.Set("login_hint", identityProvider.Config.LoginHint)
	data.Set("ui_locales", identityProvider.Config.UILocales)
	data.Set("default_scopes", identityProvider.Config.DefaultScope)

	if v, ok := data.GetOk("client_secret_wo_version"); ok && v != nil {
		data.Set("client_secret_wo_version", v.(int))
	}

	return nil
}
