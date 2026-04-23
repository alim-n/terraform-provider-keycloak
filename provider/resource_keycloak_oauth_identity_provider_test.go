package provider

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/keycloak/terraform-provider-keycloak/keycloak"
)

func TestAccKeycloakOauthIdentityProvider_basic(t *testing.T) {
	t.Parallel()

	oauthName := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories,
		PreCheck:                 func() { testAccPreCheck(t) },
		CheckDestroy:             testAccCheckKeycloakOauthIdentityProviderDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testKeycloakOauthIdentityProvider_basic(oauthName),
				Check:  testAccCheckKeycloakOauthIdentityProviderExists("keycloak_oauth_identity_provider.oauth"),
			},
		},
	})
}

func TestAccKeycloakOauthIdentityProvider_customDisplayName(t *testing.T) {
	t.Parallel()

	oauthName := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories,
		PreCheck:                 func() { testAccPreCheck(t) },
		CheckDestroy:             testAccCheckKeycloakOauthIdentityProviderDestroy(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_oauth_identity_provider" "oauth" {
	realm             = data.keycloak_realm.realm.id
	alias             = "%s"
	authorization_url = "https://example.com/auth"
	token_url         = "https://example.com/token"
	client_id         = "example_id"
	client_secret     = "example_token"

	display_name = "Example Provider"
}
	`, testAccRealm.Realm, oauthName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKeycloakOauthIdentityProviderExists("keycloak_oauth_identity_provider.oauth"),
					resource.TestCheckResourceAttr("keycloak_oauth_identity_provider.oauth", "display_name", "Example Provider"),
				),
			},
		},
	})
}

func TestAccKeycloakOauthIdentityProvider_extraConfig(t *testing.T) {
	t.Parallel()

	oauthName := acctest.RandomWithPrefix("tf-acc")
	customConfigValue := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories,
		PreCheck:                 func() { testAccPreCheck(t) },
		CheckDestroy:             testAccCheckKeycloakOauthIdentityProviderDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testKeycloakOauthIdentityProvider_extra_config(oauthName, "dummyConfig", customConfigValue),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKeycloakOauthIdentityProviderHasCustomConfigValue("keycloak_oauth_identity_provider.oauth", customConfigValue),
				),
			},
		},
	})
}

func TestAccKeycloakOauthIdentityProvider_extraConfigInvalid(t *testing.T) {
	t.Parallel()

	oauthName := acctest.RandomWithPrefix("tf-acc")
	customConfigValue := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories,
		PreCheck:                 func() { testAccPreCheck(t) },
		CheckDestroy:             testAccCheckKeycloakOauthIdentityProviderDestroy(),
		Steps: []resource.TestStep{
			{
				Config:      testKeycloakOauthIdentityProvider_extra_config(oauthName, "syncMode", customConfigValue),
				ExpectError: regexp.MustCompile("extra_config key \"syncMode\" is not allowed"),
			},
		},
	})
}

func TestAccKeycloakOauthIdentityProvider_keyDefaultScopes(t *testing.T) {
	t.Parallel()

	oauthName := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories,
		PreCheck:                 func() { testAccPreCheck(t) },
		CheckDestroy:             testAccCheckKeycloakOauthIdentityProviderDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testKeycloakOauthIdentityProvider_keyDefaultScopes(oauthName, "profile email"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKeycloakOauthIdentityProviderExists("keycloak_oauth_identity_provider.oauth"),
					testAccCheckKeycloakOauthIdentityProviderDefaultScopes("keycloak_oauth_identity_provider.oauth", "profile email"),
				),
			},
		},
	})
}

func TestAccKeycloakOauthIdentityProvider_linkOrganization(t *testing.T) {
	t.Parallel()

	oauthName := acctest.RandomWithPrefix("tf-acc")
	organizationName := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories,
		PreCheck:                 func() { testAccPreCheck(t) },
		CheckDestroy:             testAccCheckKeycloakOauthIdentityProviderDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testKeycloakOauthIdentityProvider_linkOrganization(oauthName, organizationName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKeycloakOauthIdentityProviderExists("keycloak_oauth_identity_provider.oauth"),
					testAccCheckKeycloakOauthIdentityProviderLinkOrganization("keycloak_oauth_identity_provider.oauth"),
				),
			},
		},
	})
}

func TestAccKeycloakOauthIdentityProvider_createAfterManualDestroy(t *testing.T) {
	t.Parallel()

	var oauth = &keycloak.IdentityProvider{}

	oauthName := acctest.RandomWithPrefix("tf-acc")

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories,
		PreCheck:                 func() { testAccPreCheck(t) },
		CheckDestroy:             testAccCheckKeycloakOauthIdentityProviderDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testKeycloakOauthIdentityProvider_basic(oauthName),
				Check:  testAccCheckKeycloakOauthIdentityProviderFetch("keycloak_oauth_identity_provider.oauth", oauth),
			},
			{
				PreConfig: func() {
					err := keycloakClient.DeleteIdentityProvider(testCtx, oauth.Realm, oauth.Alias)
					if err != nil {
						t.Fatal(err)
					}
				},
				Config: testKeycloakOauthIdentityProvider_basic(oauthName),
				Check:  testAccCheckKeycloakOauthIdentityProviderExists("keycloak_oauth_identity_provider.oauth"),
			},
		},
	})
}

func TestAccKeycloakOauthIdentityProvider_basicUpdateAll(t *testing.T) {
	t.Parallel()

	firstEnabled := randomBool()
	firstHideOnLogin := randomBool()

	firstOauth := &keycloak.IdentityProvider{
		Realm:       testAccRealm.Realm,
		Alias:       acctest.RandString(10),
		Enabled:     firstEnabled,
		HideOnLogin: firstHideOnLogin,
		Config: &keycloak.IdentityProviderConfig{
			AuthorizationUrl: "https://example.com/auth",
			TokenUrl:         "https://example.com/token",
			ClientId:         acctest.RandString(10),
			ClientSecret:     acctest.RandString(10),
			UserInfoUrl:      "https://example.com/userinfo",
			GuiOrder:         strconv.Itoa(acctest.RandIntRange(1, 3)),
			SyncMode:         randomStringInSlice(syncModes),
		},
	}

	secondOauth := &keycloak.IdentityProvider{
		Realm:       testAccRealm.Realm,
		Alias:       acctest.RandString(10),
		Enabled:     !firstEnabled,
		HideOnLogin: !firstHideOnLogin,
		Config: &keycloak.IdentityProviderConfig{
			AuthorizationUrl: "https://example.com/auth2",
			TokenUrl:         "https://example.com/token2",
			ClientId:         acctest.RandString(10),
			ClientSecret:     acctest.RandString(10),
			UserInfoUrl:      "https://example.com/userinfo2",
			GuiOrder:         strconv.Itoa(acctest.RandIntRange(1, 3)),
			SyncMode:         randomStringInSlice(syncModes),
		},
	}

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories,
		PreCheck:                 func() { testAccPreCheck(t) },
		CheckDestroy:             testAccCheckKeycloakOauthIdentityProviderDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testKeycloakOauthIdentityProvider_basicFromInterface(firstOauth),
				Check:  testAccCheckKeycloakOauthIdentityProviderExists("keycloak_oauth_identity_provider.oauth"),
			},
			{
				Config: testKeycloakOauthIdentityProvider_basicFromInterface(secondOauth),
				Check:  testAccCheckKeycloakOauthIdentityProviderExists("keycloak_oauth_identity_provider.oauth"),
			},
		},
	})
}

func TestAccKeycloakOauthIdentityProvider_clientSecretWriteOnly(t *testing.T) {
	t.Parallel()

	oauthName := acctest.RandomWithPrefix("tf-acc")
	clientSecretWO := acctest.RandomWithPrefix("tf-acc")
	clientSecretWOVersion := 1

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProtoV5ProviderFactories,
		PreCheck:                 func() { testAccPreCheck(t) },
		CheckDestroy:             testAccCheckKeycloakOauthIdentityProviderDestroy(),
		Steps: []resource.TestStep{
			{
				Config: testKeycloakOauthIdentityProvider_clientSecretWriteOnly(oauthName, clientSecretWO, clientSecretWOVersion),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckKeycloakOauthIdentityProviderExists("keycloak_oauth_identity_provider.oauth"),
					resource.TestCheckNoResourceAttr("keycloak_oauth_identity_provider.oauth", "client_secret"),
					resource.TestCheckResourceAttr("keycloak_oauth_identity_provider.oauth", "client_secret_wo_version", strconv.Itoa(clientSecretWOVersion)),
				),
			},
		},
	})
}

func testAccCheckKeycloakOauthIdentityProviderExists(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		_, err := getKeycloakOauthIdentityProviderFromState(s, resourceName)
		if err != nil {
			return err
		}

		return nil
	}
}

func testAccCheckKeycloakOauthIdentityProviderFetch(resourceName string, oauth *keycloak.IdentityProvider) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		fetchedOauth, err := getKeycloakOauthIdentityProviderFromState(s, resourceName)
		if err != nil {
			return err
		}

		oauth.Alias = fetchedOauth.Alias
		oauth.Realm = fetchedOauth.Realm

		return nil
	}
}

func testAccCheckKeycloakOauthIdentityProviderHasCustomConfigValue(resourceName, customConfigValue string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		fetchedOauth, err := getKeycloakOauthIdentityProviderFromState(s, resourceName)
		if err != nil {
			return err
		}

		if fetchedOauth.Config.ExtraConfig["dummyConfig"].(string) != customConfigValue {
			return fmt.Errorf("expected custom oauth provider to have config with a custom key 'dummyConfig' with a value %s, but value was %s", customConfigValue, fetchedOauth.Config.ExtraConfig["dummyConfig"].(string))
		}

		return nil
	}
}

func testAccCheckKeycloakOauthIdentityProviderDefaultScopes(resourceName, value string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		fetchedOauth, err := getKeycloakOauthIdentityProviderFromState(s, resourceName)
		if err != nil {
			return err
		}

		if fetchedOauth.Config.DefaultScope != value {
			return fmt.Errorf("expected oauth provider to have value %s for key 'defaultScope', but value was %s", value, fetchedOauth.Config.DefaultScope)
		}

		return nil
	}
}

func testAccCheckKeycloakOauthIdentityProviderLinkOrganization(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		fetchedOauth, err := getKeycloakOauthIdentityProviderFromState(s, resourceName)
		if err != nil {
			return err
		}

		if fetchedOauth.OrganizationId == "" {
			return fmt.Errorf("expected oauth provider to be linked with an organization, but it was not")
		}

		return nil
	}
}

func testAccCheckKeycloakOauthIdentityProviderDestroy() resource.TestCheckFunc {
	return func(s *terraform.State) error {
		for _, rs := range s.RootModule().Resources {
			if rs.Type != "keycloak_oauth_identity_provider" {
				continue
			}

			id := rs.Primary.ID
			realm := rs.Primary.Attributes["realm"]

			oauth, _ := keycloakClient.GetIdentityProvider(testCtx, realm, id)
			if oauth != nil {
				return fmt.Errorf("oauth config with id %s still exists", id)
			}
		}

		return nil
	}
}

func getKeycloakOauthIdentityProviderFromState(s *terraform.State, resourceName string) (*keycloak.IdentityProvider, error) {
	rs, ok := s.RootModule().Resources[resourceName]
	if !ok {
		return nil, fmt.Errorf("resource not found: %s", resourceName)
	}

	realm := rs.Primary.Attributes["realm"]
	alias := rs.Primary.Attributes["alias"]

	oauth, err := keycloakClient.GetIdentityProvider(testCtx, realm, alias)
	if err != nil {
		return nil, fmt.Errorf("error getting oauth identity provider config with alias %s: %s", alias, err)
	}

	return oauth, nil
}

func testKeycloakOauthIdentityProvider_basic(oauth string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_oauth_identity_provider" "oauth" {
	realm             = data.keycloak_realm.realm.id
	alias             = "%s"
	authorization_url = "https://example.com/auth"
	token_url         = "https://example.com/token"
	client_id         = "example_id"
	client_secret     = "example_token"
}
	`, testAccRealm.Realm, oauth)
}

func testKeycloakOauthIdentityProvider_extra_config(alias, configKey, configValue string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_oauth_identity_provider" "oauth" {
	realm             = data.keycloak_realm.realm.id
	provider_id       = "oauth2"
	alias             = "%s"
	authorization_url = "https://example.com/auth"
	token_url         = "https://example.com/token"
	client_id         = "example_id"
	client_secret     = "example_token"
	extra_config      = {
		%s = "%s"
	}
}
	`, testAccRealm.Realm, alias, configKey, configValue)
}

func testKeycloakOauthIdentityProvider_keyDefaultScopes(alias, value string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_oauth_identity_provider" "oauth" {
	realm             = data.keycloak_realm.realm.id
	provider_id       = "oauth2"
	alias             = "%s"
	authorization_url = "https://example.com/auth"
	token_url         = "https://example.com/token"
	client_id         = "example_id"
	client_secret     = "example_token"
	default_scopes    = "%s"
}
	`, testAccRealm.Realm, alias, value)
}

func testKeycloakOauthIdentityProvider_basicFromInterface(oauth *keycloak.IdentityProvider) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_oauth_identity_provider" "oauth" {
	realm              = data.keycloak_realm.realm.id
	alias              = "%s"
	enabled            = %t
	authorization_url  = "%s"
	token_url          = "%s"
	user_info_url      = "%s"
	client_id          = "%s"
	client_secret      = "%s"
	gui_order          = %s
	sync_mode          = "%s"
	hide_on_login_page = %t
}
	`, testAccRealm.Realm, oauth.Alias, oauth.Enabled, oauth.Config.AuthorizationUrl, oauth.Config.TokenUrl, oauth.Config.UserInfoUrl, oauth.Config.ClientId, oauth.Config.ClientSecret, oauth.Config.GuiOrder, oauth.Config.SyncMode, oauth.HideOnLogin)
}

func testKeycloakOauthIdentityProvider_linkOrganization(oauth, organizationName string) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_organization" "org" {
	realm   = data.keycloak_realm.realm.id
	name    = "%s"
	enabled = true

	domain {
		name     = "example.com"
		verified = true
 	}
}

resource "keycloak_oauth_identity_provider" "oauth" {
	realm             = data.keycloak_realm.realm.id
	alias             = "%s"
	authorization_url = "https://example.com/auth"
	token_url         = "https://example.com/token"
	client_id         = "example_id"
	client_secret     = "example_token"

	organization_id                 = keycloak_organization.org.id
	org_domain                      = "example.com"
	org_redirect_mode_email_matches = true
}
	`, testAccRealm.Realm, organizationName, oauth)
}

func testKeycloakOauthIdentityProvider_clientSecretWriteOnly(oauth, clientSecretWriteOnly string, clientSecretWriteOnlyVersion int) string {
	return fmt.Sprintf(`
data "keycloak_realm" "realm" {
	realm = "%s"
}

resource "keycloak_oauth_identity_provider" "oauth" {
	realm                    = data.keycloak_realm.realm.id
	alias                    = "%s"
	authorization_url        = "https://example.com/auth"
	token_url                = "https://example.com/token"
	client_id                = "example_id"
	client_secret_wo         = "%s"
	client_secret_wo_version = "%d"
}
	`, testAccRealm.Realm, oauth, clientSecretWriteOnly, clientSecretWriteOnlyVersion)
}
