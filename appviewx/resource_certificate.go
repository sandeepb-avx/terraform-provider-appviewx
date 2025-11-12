package appviewx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"terraform-provider-appviewx/appviewx/config"
	"terraform-provider-appviewx/appviewx/constants"
)

func ResourceCertificateServer() *schema.Resource {
	//fmt.Println("****************** Logging for test purpose")
	return &schema.Resource{
		Create: resourceCertificateServerCreate,
		Read:   resourceCertificateServerRead,
		Update: resourceCertificateServerUpdate,
		Delete: resourceCertificateServerDelete,

		Schema: map[string]*schema.Schema{
			constants.COMMON_NAME: &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
			constants.HASH_FUNCTION: &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
			constants.KEY_TYPE: &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
			constants.BIT_LENGTH: &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
			constants.DNS_NAMES: &schema.Schema{
				Type:     schema.TypeList,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
			},
			constants.CUSTOM_FIELDS: &schema.Schema{
				Type:     schema.TypeMap,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
			},
			constants.VENDOR_SPECIFIC_FIELDS: &schema.Schema{
				Type:     schema.TypeMap,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Optional: true,
			},
			constants.CERTIFICATE_AUTHORITY: &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
			constants.CERTIFICATE_GROUP_NAME: &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
			constants.CA_SETTING_NAME: &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
			constants.CERTIFICATE_TYPE: &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
			constants.VALIDITY: &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
			constants.VALIDITY_UNIT: &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
			constants.VALIDITY_UNIT_VALUE: &schema.Schema{
				Type:     schema.TypeInt,
				Optional: true,
			},
			constants.IS_SYNC: &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
			},
			constants.CERTIFICATE_DOWNLOAD_PATH: &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
			constants.CERTIFICATE_DOWNLOAD_FORMAT: &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
			constants.CERTIFICATE_DOWNLOAD_PASSWORD: &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
			constants.CERTIFICATE_CHAIN_REQUIRED: &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
			},
			constants.RESOURCE_ID: &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
			constants.KEY_DOWNLOAD_PATH: &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
			constants.KEY_DOWNLOAD_PASSWORD: &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
			constants.DOWNLOAD_PASSWORD_PROTECTED_KEY: &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: resourceCertificateImport,
		},
	}
}

func resourceCertificateImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	parameters := strings.Split(id, ",")

	log.Println("parameters = ", parameters)

	return []*schema.ResourceData{d}, nil
}

func resourceCertificateServerRead(d *schema.ResourceData, m interface{}) error {
	log.Println("[INFO]  **************** GET OPERATION NOT SUPPORTED FOR THIS RESOURCE **************** ")
	// Since the resource is for stateless operation, only nil returned
	return nil
}

func resourceCertificateServerUpdate(resourceData *schema.ResourceData, m interface{}) error {
	log.Println("[INFO]  **************** UPDATE OPERATION NOT SUPPORTED FOR THIS RESOURCE **************** ")
	//Update implementation is empty since this resource is for the stateless generic api invocation
	return errors.New("Update not supported")
}

func resourceCertificateServerDelete(d *schema.ResourceData, m interface{}) error {
	log.Println("[INFO]  **************** DELETE OPERATION NOT SUPPORTED FOR THIS RESOURCE **************** ")
	// Delete implementation is empty since this resoruce is for the stateless generic api invocation
	d.SetId("")
	return nil
}

// TODO: cleanup to be done
func resourceCertificateServerCreate(resourceData *schema.ResourceData, m interface{}) error {

	log.Println("****************** Resource Certificate Server Create ******************")
	configAppViewXEnvironment := m.(*config.AppViewXEnvironment)

	appviewxUserName := configAppViewXEnvironment.AppViewXUserName
	appviewxPassword := configAppViewXEnvironment.AppViewXPassword
	appviewxClientId := configAppViewXEnvironment.AppViewXClientId
	appviewxClientSecret := configAppViewXEnvironment.AppViewXClientSecret
	appviewxEnvironmentIP := configAppViewXEnvironment.AppViewXEnvironmentIP
	appviewxEnvironmentPort := configAppViewXEnvironment.AppViewXEnvironmentPort
	appviewxEnvironmentIsHTTPS := configAppViewXEnvironment.AppViewXIsHTTPS
	appviewxGwSource := "WEB"
	var appviewxSessionID, accessToken string
	var err error
	if appviewxUserName != "" && appviewxPassword != "" {
		appviewxSessionID, err = GetSession(appviewxUserName, appviewxPassword, appviewxEnvironmentIP, appviewxEnvironmentPort, appviewxGwSource, appviewxEnvironmentIsHTTPS)
		if err != nil {
			log.Println("[ERROR] Error in getting the session due to : ", err)
			return nil
		}
	} else if appviewxClientId != "" && appviewxClientSecret != "" {
		accessToken, err = GetAccessToken(appviewxClientId, appviewxClientSecret, appviewxEnvironmentIP, appviewxEnvironmentPort, appviewxGwSource, appviewxEnvironmentIsHTTPS)
		if err != nil {
			log.Println("[ERROR] Error in getting the access token due to : ", err)
			return nil
		}
	}

	result, err := createCertificate(resourceData, configAppViewXEnvironment, appviewxSessionID, accessToken)
	if err != nil {
		log.Println("[ERROR] Error in creating the certificate due to : ", err)
		return err
	}
	if result.Response["resourceId"] == "" {
		log.Println("[ERROR] Resource ID is not obtained from the certificate creation response to proceed with certificate download")
		return errors.New("[ERROR] Resource ID is not obtained to proceed with certificate download")
	}
	resourceID := result.Response["resourceId"]
	resourceData.Set(constants.RESOURCE_ID, resourceID)
	resourceData.SetId(resourceID)
	log.Println("[INFO] resource_id data is set in payload")

	if resourceData.Get(constants.IS_SYNC) == nil || !resourceData.Get(constants.IS_SYNC).(bool) {
		log.Println("[INFO] Certificate is created in ASYNC mode so download can be done once the certificate is issued.")
		log.Println("[INFO] ***** Use this resource ID to download the certificate", resourceID)
		resourceData.SetId(strconv.Itoa(rand.Int()))
		return nil
	} else {
		log.Println("[INFO] Certificate is created in SYNC mode so proceeding with download.")
		if err := downloadCertificate(resourceData, resourceID, appviewxSessionID, accessToken, configAppViewXEnvironment); err != nil {
			return err
		}
		if resourceData.Get(constants.KEY_DOWNLOAD_PATH).(string) != "" {
			log.Println("[INFO] Key download path is provided in the payload hence proceeding with key download")
			if err := downloadKey(resourceData, resourceID, appviewxSessionID, accessToken, configAppViewXEnvironment); err != nil {
				return err
			}
		}
	}
	return nil
}

func downloadCertificate(resourceData *schema.ResourceData, resourceID string, appviewxSessionID string, accessToken string, configAppViewXEnvironment *config.AppViewXEnvironment) error {
	var isChainRequired, ok bool
	var downloadPassword string
	commonName := resourceData.Get(constants.COMMON_NAME).(string)

	downloadFormat := GetDownloadFormat(resourceData)
	downloadPath := GetDownloadFilePath(resourceData, commonName, downloadFormat)
	if downloadPassword, ok = GetDownloadPassword(resourceData, downloadFormat, configAppViewXEnvironment); !ok {
		return errors.New("[ERROR] Error in getting the download password")
	}
	isChainRequired = resourceData.Get(constants.CERTIFICATE_CHAIN_REQUIRED).(bool)

	if downloadSuccess := downloadCertificateFromAppviewx(resourceID, "", "", downloadFormat, downloadPassword, downloadPath, isChainRequired, appviewxSessionID, accessToken, configAppViewXEnvironment); downloadSuccess {
		log.Println("[INFO] Certificate downloaded successfully in the specified path")
		resourceData.SetId(strconv.Itoa(rand.Int()))
	} else {
		log.Println("[ERROR] Certificate was not downloaded in the specified path")
		return errors.New("[ERROR] Certificate was not downloaded in the specified path")
	}
	return nil
}

func GetAccessToken(appviewxClientId, appviewxClientSecret, appviewxEnvironmentIP,
	appviewxEnvironmentPort,
	appviewxGwSource string,
	appviewxEnvironmentIsHTTPS bool) (string, error) {
	log.Println("[INFO] Request received for fetching access token")

	headers := make(map[string]interface{})
	headers[constants.CONTENT_TYPE] = constants.APPLICATION_URL_ENCODED
	headers[constants.ACCEPT] = constants.APPLICATION_JSON

	actionID := constants.APPVIEWX_GET_ACCESS_TOKEN_ACTION_ID

	queryParams := make(map[string]string)
	queryParams[constants.GW_SOURCE] = appviewxGwSource

	payload := url.Values{}
	payload.Set(constants.GRANT_TYPE, constants.CLIENT_CREDENTIALS)

	url := GetURL(appviewxEnvironmentIP, appviewxEnvironmentPort, actionID, queryParams, appviewxEnvironmentIsHTTPS)

	client := &http.Client{Transport: HTTPTransport()}
	req, err := http.NewRequest(constants.POST, url, strings.NewReader(payload.Encode()))
	req.SetBasicAuth(appviewxClientId, appviewxClientSecret)
	if err != nil {
		log.Println("[ERROR] Error in creating the new reqeust", err)
		return "", err
	}

	for key, value := range headers {
		value1 := fmt.Sprintf("%v", value)
		key1 := fmt.Sprintf("%v", key)
		req.Header.Add(key1, value1)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Println("[ERROR] Error in executing the request", err)
		return "", err
	}
	log.Println("[INFO] Response status code : ", resp.Status)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseBody, err := io.ReadAll(resp.Body)
		if err == nil {
			log.Println("[ERROR] Response obtained : ", string(responseBody))
			return "", errors.New("error in getting the access token due to " + string(responseBody))
		}
	}
	defer resp.Body.Close()
	responseContents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("[ERROR] error in reading the response body", err)
		return "", err
	}

	response := make(map[string]interface{})
	err = json.Unmarshal(responseContents, &response)
	if err != nil {
		log.Println("[ERROR] Error in Unmarshalling the responseContents", err)
		return "", err
	}

	if response[constants.RESPONSE] != nil {
		log.Println("[INFO] Access token retrieval success, access token will be used for AppViewX API calls")
		return response[constants.RESPONSE].(string), nil
	}
	log.Println("[ERROR] Access token retrieval failed")
	return "", errors.New("access token retrieval failed")
}

func createCertificate(resourceData *schema.ResourceData, configAppViewXEnvironment *config.AppViewXEnvironment, appviewxSessionID, accessToken string) (config.AppviewxCreateCertResponse, error) {
	var result config.AppviewxCreateCertResponse
	httpMethod := config.HTTPMethodPost
	appviewxEnvironmentIP := configAppViewXEnvironment.AppViewXEnvironmentIP
	appviewxEnvironmentPort := configAppViewXEnvironment.AppViewXEnvironmentPort
	appviewxEnvironmentIsHTTPS := configAppViewXEnvironment.AppViewXIsHTTPS
	queryParams := frameQueryParams()
	if resourceData.Get(constants.IS_SYNC) != nil {
		isSync := resourceData.Get(constants.IS_SYNC).(bool)
		queryParams["isSync"] = strconv.FormatBool(isSync)
	}
	headers := frameHeaders()
	url := GetURL(appviewxEnvironmentIP, appviewxEnvironmentPort, config.CreateCertificateActionId, queryParams, appviewxEnvironmentIsHTTPS)
	payload := frameCertificatePayload(resourceData)
	requestBody, err := json.Marshal(payload)
	if err != nil {
		log.Println("[ERROR] error in Marshalling the payload ", payload, err)
		return result, err
	}
	client := &http.Client{Transport: HTTPTransport()}

	printRequest(httpMethod, url, headers, requestBody)

	req, err := http.NewRequest(httpMethod, url, bytes.NewBuffer(requestBody))
	if err != nil {
		log.Println("[ERROR] error in creating new Request", err)
		return result, err
	}

	for key, value := range headers {
		value1 := fmt.Sprintf("%v", value)
		key1 := fmt.Sprintf("%v", key)
		req.Header.Add(key1, value1)
	}
	if appviewxSessionID != "" {
		req.Header.Add(constants.SESSION_ID, appviewxSessionID)
	} else {
		req.Header.Add(constants.TOKEN, accessToken)
	}

	httpResponse, err := client.Do(req)
	if err != nil {
		log.Println("[ERROR] Error in making certificate create request due to ", err)
		return result, err
	} else {
		log.Println("[INFO] Certificate creation request submitted successfully")
	}
	log.Println("[INFO] Response status code : ", httpResponse.Status)
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		responseBody, err := io.ReadAll(httpResponse.Body)
		if err == nil {
			log.Println("[ERROR] Response obtained : ", string(responseBody))
			return result, errors.New("error in creating the certificate due to " + string(responseBody))
		}
	}
	responseByte, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		log.Println(err)
		return result, err
	} else {
		err = json.Unmarshal(responseByte, &result)
		if err != nil {
			log.Println("[ERROR] Unable to unmarshall the response due to ", err)
			return result, err
		} else {
			log.Println("[INFO] Response obtained successfully for certificate create")
		}
	}
	return result, nil

}

func frameCertificatePayload(resourceData *schema.ResourceData) config.CreateCertificatePayload {
	var payload config.CreateCertificatePayload
	var csrParams config.CSRParameters
	csrParams.CommonName = resourceData.Get(constants.COMMON_NAME).(string)
	csrParams.HashFunction = resourceData.Get(constants.HASH_FUNCTION).(string)
	csrParams.KeyType = resourceData.Get(constants.KEY_TYPE).(string)
	csrParams.BitLength = resourceData.Get(constants.BIT_LENGTH).(string)
	dnsNames, ok := resourceData.GetOk(constants.DNS_NAMES)
	var enhancedSAN config.EnhancedSANTypes
	if ok {
		dns := dnsNames.([]interface{})
		var dnsValues = make([]string, len(dns))
		for key, value := range dns {
			dnsValues[key] = value.(string)
		}
		enhancedSAN.DNSNames = dnsValues
		csrParams.EnhancedSANTypes = enhancedSAN
	}
	csrParams.CertificateCategories = []string{"Server", "Client"}
	payload.CaConnectorInfo.CSRParameters = csrParams
	payload.CaConnectorInfo.CASettingName = resourceData.Get(constants.CA_SETTING_NAME).(string)
	payload.CaConnectorInfo.CertificateAuthority = resourceData.Get(constants.CERTIFICATE_AUTHORITY).(string)
	payload.CaConnectorInfo.CAConnectorName = payload.CaConnectorInfo.CertificateAuthority + " Connector  Terraform"
	payload.CaConnectorInfo.ValidityInDays = resourceData.Get(constants.VALIDITY).(int)
	payload.CaConnectorInfo.ValidityUnit = resourceData.Get(constants.VALIDITY_UNIT).(string)
	payload.CaConnectorInfo.ValidityUnitValue = resourceData.Get(constants.VALIDITY_UNIT_VALUE).(int)
	payload.CaConnectorInfo.CertificateType = resourceData.Get(constants.CERTIFICATE_TYPE).(string)
	payload.CertificateGroup.CertificateGroupName = resourceData.Get(constants.CERTIFICATE_GROUP_NAME).(string)
	customFields, ok := resourceData.GetOk(constants.CUSTOM_FIELDS)
	if ok {
		var customFieldValues = make(map[string]string)
		customFields := customFields.(map[string]interface{})
		for key, values := range customFields {
			customFieldValues[key] = values.(string)
		}
		payload.CaConnectorInfo.CustomAttributes = customFieldValues
	}
	vendorSpecFields, ok := resourceData.GetOk(constants.VENDOR_SPECIFIC_FIELDS)
	if ok {
		var vendorFields = make(map[string]string)
		vendorSpecFieldList := vendorSpecFields.(map[string]interface{})
		for key, values := range vendorSpecFieldList {
			vendorFields[key] = values.(string)
		}
		payload.CaConnectorInfo.VendorSpecificfields = vendorFields
	}
	return payload
}

func frameHeaders() map[string]interface{} {
	var headers = make(map[string]interface{})
	headers["Content-Type"] = "application/json"
	headers["Accept"] = "application/json"
	return headers
}

func frameQueryParams() map[string]string {
	var queryParams = make(map[string]string)
	queryParams[constants.GW_SOURCE] = "WEB"
	return queryParams
}
