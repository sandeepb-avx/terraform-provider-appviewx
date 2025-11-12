package appviewx

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"terraform-provider-appviewx/appviewx/config"
	"terraform-provider-appviewx/appviewx/constants"
	"terraform-provider-appviewx/appviewx/logger"
)

func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			constants.APPVIEWX_USERNAME: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("APPVIEWX_TERRAFORM_USERNAME", nil),
				Description: "AppViewX Username",
				Sensitive:   true,
			},
			constants.APPVIEWX_PASSWORD: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("APPVIEWX_TERRAFORM_PASSWORD", nil),
				Description: "AppViewX Password",
				Sensitive:   true,
			},
			constants.APPVIEWX_CLIENT_ID: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("APPVIEWX_TERRAFORM_CLIENT_ID", nil),
				Description: "AppViewX Client ID",
				Sensitive:   true,
			},
			constants.APPVIEWX_CLIENT_SECRET: {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("APPVIEWX_TERRAFORM_CLIENT_SECRET", nil),
				Description: "AppViewX Client Secret",
				Sensitive:   true,
			},
			constants.APPVIEWX_ENVIRONMENT_IP: {
				Type:     schema.TypeString,
				Required: true,
			},
			constants.APPVIEWX_ENVIRONMENT_PORT: {
				Type:     schema.TypeString,
				Required: true,
			},
			constants.APPVIEWX_ENVIRONMENT_Is_HTTPS: {
				Type:     schema.TypeBool,
				Required: true,
			},
			constants.LOG_LEVEL: {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "INFO",
				Description: "Log level (DEBUG, INFO)",
				ValidateFunc: validation.StringInSlice([]string{
					"DEBUG", "INFO",
				}, false),
			},
			constants.CERTIFICATE_DOWNLOAD_PASSWORD: {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Default certificate download password (provider level) - takes priority over resource level",
			},
			constants.KEY_DOWNLOAD_PASSWORD: {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Default key download password (provider level) - takes priority over resource level",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"appviewx_automation":                             ResourceAutomationServer(),
			"appviewx_create_certificate":                     ResourceCertificateServer(),
			"appviewx_download_certificate":                   ResourceDownloadCertificateServer(),
			"appviewx_search_certificate":                     ResourceSearchCertificateByKeyword(),
			"appviewx_revoke_certificate":                     ResourceRevokeCertificate(),
			"appviewx_certificate_push_akv":                   ResourceCertificatePushAKV(),
			"appviewx_create_push_certificate_request_status": CreatePushCertificateRequestStatus(),
			"appviewx_revoke_certificate_request_status":      RevokeCertificateRequestStatus(),
		},
		ConfigureFunc: providerConfigure,
	}
}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	appviewxEnvironment := config.AppViewXEnvironment{
		AppViewXUserName:             d.Get(constants.APPVIEWX_USERNAME).(string),
		AppViewXPassword:             d.Get(constants.APPVIEWX_PASSWORD).(string),
		AppViewXClientId:             d.Get(constants.APPVIEWX_CLIENT_ID).(string),
		AppViewXClientSecret:         d.Get(constants.APPVIEWX_CLIENT_SECRET).(string),
		AppViewXEnvironmentIP:        d.Get(constants.APPVIEWX_ENVIRONMENT_IP).(string),
		AppViewXEnvironmentPort:      d.Get(constants.APPVIEWX_ENVIRONMENT_PORT).(string),
		AppViewXIsHTTPS:              d.Get(constants.APPVIEWX_ENVIRONMENT_Is_HTTPS).(bool),
		ProviderCertDownloadPassword: d.Get(constants.CERTIFICATE_DOWNLOAD_PASSWORD).(string),
		ProviderKeyDownloadPassword:  d.Get(constants.KEY_DOWNLOAD_PASSWORD).(string),
	}

	logLevel := d.Get("log_level").(string)
	logger.SetLevel(logLevel)
	logger.Info("AppViewX Provider initialized with log level: %s", logLevel)
	return &appviewxEnvironment, nil
}