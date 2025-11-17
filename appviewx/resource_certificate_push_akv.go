package appviewx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"terraform-provider-appviewx/appviewx/config"
	"terraform-provider-appviewx/appviewx/constants"
	"terraform-provider-appviewx/appviewx/logger"
)

func ResourceCertificatePushAKV() *schema.Resource {
	return &schema.Resource{
		Create: resourceCertificatePushAKVCreate,
		Read:   resourceCertificatePushAKVRead,
		Delete: resourceCertificatePushAKVDelete,
		Update: resourceCertificatePushAKVUpdate,

		Schema: map[string]*schema.Schema{
			"field_info": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "JSON string containing all certificate and key vault configuration",
				Sensitive:   true,
			},
			"workflow_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The workflow name to execute",
			},
			"status_code": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "HTTP status code from the response",
			},
			"workflow_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Workflow request ID if successful",
			},
			"success": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the request was successful",
			},
			"certificate_common_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Common name of the certificate being pushed (e.g., 'www.example.com')",
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: resourceCertificateImport,
		},
	}
}

func resourceCertificatePushAKVRead(d *schema.ResourceData, m interface{}) error {
	logger.Info("**************** GET OPERATION - PRESERVING STATE **************** ")

	return nil
}

func resourceCertificatePushAKVDelete(d *schema.ResourceData, m interface{}) error {
	logger.Info("**************** DELETE OPERATION FOR CERTIFICATE PUSH AKV **************** ")
	// Since this is a create-only resource, deletion just removes it from state
	d.SetId("")
	return nil
}

func resourceCertificatePushAKVUpdate(d *schema.ResourceData, m interface{}) error {
	logger.Info("**************** UPDATE OPERATION FOR CERTIFICATE PUSH AKV **************** ")
	// Since this is a create-only resource, update just removes it from state
	return nil
}

func resourceCertificatePushAKVCreate(d *schema.ResourceData, m interface{}) error {
	logger.Info("**************** CREATE OPERATION FOR CERTIFICATE PUSH AKV **************** ")
	configAppViewXEnvironment := m.(*config.AppViewXEnvironment)
	// d.Partial(true)

	// Authentication
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

	// Try username/password authentication
	if appviewxUserName != "" && appviewxPassword != "" {
		appviewxSessionID, err = GetSession(appviewxUserName, appviewxPassword, appviewxEnvironmentIP, appviewxEnvironmentPort, appviewxGwSource, appviewxEnvironmentIsHTTPS)
		if err != nil {
			logger.Error(" Error in getting the session due to : ", err)
			// Don't return error here, try client ID/secret authentication
		}
	}

	// If username/password authentication failed or wasn't provided, try client ID/secret
	if appviewxSessionID == "" && appviewxClientId != "" && appviewxClientSecret != "" {
		accessToken, err = GetAccessToken(appviewxClientId, appviewxClientSecret, appviewxEnvironmentIP, appviewxEnvironmentPort, appviewxGwSource, appviewxEnvironmentIsHTTPS)
		if err != nil {
			logger.Error(" Error in getting the access token due to : ", err)
			return err
		}
	}

	// If both authentication methods failed, return error
	if appviewxSessionID == "" && accessToken == "" {
		return errors.New("authentication failed - provide either username/password or client ID/secret in Terraform File or in the Environment Variables:[APPVIEWX_TERRAFORM_CLIENT_ID, APPVIEWX_TERRAFORM_CLIENT_SECRET]")
	}

	// Parse the field_info JSON string
	fieldInfoString := d.Get("field_info").(string)
	var fieldInfo map[string]interface{}

	// Temporarily parse to get the common name
	var tempFieldInfo map[string]interface{}
	if err := json.Unmarshal([]byte(fieldInfoString), &tempFieldInfo); err == nil {
		if certificateCommonName, ok := tempFieldInfo["cn"]; ok {
			logger.Debug(" Certificate Common Name from field_info: %v", certificateCommonName)
			d.Set("certificate_common_name", certificateCommonName)
		}
	}

	err = json.Unmarshal([]byte(fieldInfoString), &fieldInfo)
	if err != nil {
		logger.Error(" Error parsing field_info JSON: %v", err)
		return fmt.Errorf("invalid field_info JSON: %v", err)
	}

	// Get workflow name
	workflowName := d.Get("workflow_name").(string)

	// Build the full payload structure
	payload := map[string]interface{}{
		"payload": map[string]interface{}{
			"header": map[string]interface{}{
				"workflowName": workflowName,
			},
			"data": map[string]interface{}{
				"input": map[string]interface{}{
					"requestData": []map[string]interface{}{
						{
							"sequenceNo": 1,
							"scenario":   "scenario",
							"fieldInfo":  fieldInfo,
						},
					},
				},
				"globalData":  map[string]interface{}{},
				"task_action": 1,
			},
		},
	}

	// Pretty print payload for debugging
	payloadBytes, _ := json.MarshalIndent(payload, "", "  ")
	logger.Debug("\n Certificate Push AKV payload:\n%s\n", string(payloadBytes))

	// Set action ID
	actionID := "visualworkflow-submit-request"

	// Set query parameters
	queryParams := map[string]string{
		constants.GW_SOURCE: appviewxGwSource,
	}

	// Get URL
	url := GetURL(appviewxEnvironmentIP, appviewxEnvironmentPort, actionID, queryParams, appviewxEnvironmentIsHTTPS)

	// Set headers
	headers := map[string]interface{}{
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}

	// Create HTTP client
	client := &http.Client{Transport: HTTPTransport()}
	requestBody, err := json.Marshal(payload)
	if err != nil {
		logger.Error(" Error in Marshalling the payload", err)
		return err
	}

	// Create request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		logger.Error(" Error in creating the new request ", err)
		return err
	}

	// Set headers
	for key, value := range headers {
		value1 := fmt.Sprintf("%v", value)
		key1 := fmt.Sprintf("%v", key)
		req.Header.Add(key1, value1)
	}

	// Add authentication header
	if appviewxSessionID != "" {
		logger.Debug("Using session ID for authentication")
		req.Header.Set(constants.SESSION_ID, appviewxSessionID)
	} else if accessToken != "" {
		logger.Debug("Using access token for authentication")
		req.Header.Set(constants.TOKEN, accessToken)
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Error in making http request", err)
		return err
	}
	defer resp.Body.Close()

	// Save status code
	d.Set("status_code", resp.StatusCode)

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Error in reading the response body:", err)
		return err
	}

	// Pretty print response for debugging
	var prettyResp bytes.Buffer
	if json.Indent(&prettyResp, body, "", "  ") == nil {
		logger.Info("\nResponse body:\n%s\n", prettyResp.String())
	} else {
		logger.Info("\nResponse body (raw):\n%s\n", string(body))
	}

	// Extract workflow ID from response if successful
	var responseObj map[string]interface{}
	var success bool = false
	var workflowId string = ""

	if err := json.Unmarshal(body, &responseObj); err == nil {
		if resp, ok := responseObj["response"].(map[string]interface{}); ok {
			success = true

			// Extract requestId from the correct location in the response
			if requestId, ok := resp["requestId"].(string); ok && requestId != "" {
				workflowId = requestId
				d.Set("workflow_id", requestId)
				logger.Info("Extracted workflow request ID: %s", requestId)
			} else {
				// Fallback to older path in case API structure changes
				if data, ok := resp["data"].(map[string]interface{}); ok {
					if wfId, ok := data["workflowId"].(string); ok && wfId != "" {
						workflowId = wfId
						d.Set("workflow_id", wfId)
						logger.Info("Extracted workflow ID from data.workflowId: %s", wfId)
					}
				}
			}

			if workflowId == "" {
				d.Set("workflow_id", "")
				logger.Warn("Could not extract workflow ID from response")
			}
		}
	}

	// Set success and use the workflow ID as the resource ID
	d.Set("success", success)

	// Use the workflow ID as the resource ID if available, otherwise use a random ID
	if workflowId != "" {
		d.SetId(workflowId)
	} else {
		d.SetId(strconv.Itoa(rand.Int()))
	}

	// Check final operation status and throw error if failed
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("certificate push to AKV failed with status %d: %s", resp.StatusCode, string(body))
	}

	if !success {
		return fmt.Errorf("certificate push to AKV operation failed - unable to extract workflow ID from response: %s", string(body))
	}

	// Return the read function to ensure state is properly maintained
	return resourceCertificatePushAKVRead(d, m)
}
