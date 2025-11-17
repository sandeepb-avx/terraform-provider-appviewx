package appviewx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"terraform-provider-appviewx/appviewx/config"
	"terraform-provider-appviewx/appviewx/constants"
	"terraform-provider-appviewx/appviewx/logger"
)

// Status code constants
const (
	STATUS_IN_PROGRESS = 0
	STATUS_SUCCESS     = 1
)

// Failed status codes
var failedStatusCodes = []int{2, 3, 8, 9, 10, 11}

func CreatePushCertificateRequestStatus() *schema.Resource {
	return &schema.Resource{
		Create: createPushCertificateRequestStatusCreate,
		Read:   createPushCertificateRequestStatusRead,
		Delete: createPushCertificateRequestStatusDelete,
		Update: createPushCertificateRequestStatusUpdate,

		Schema: map[string]*schema.Schema{
			"request_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Request ID from a workflow execution",
			},
			"retry_count": {
				Type:         schema.TypeInt,
				Optional:     true,
				Default:      10,
				Description:  "Number of times to retry checking workflow status (default: 10)",
				ValidateFunc: validation.IntAtLeast(1),
			},
			"retry_interval": {
				Type:         schema.TypeInt,
				Optional:     true,
				Default:      20,
				Description:  "Seconds to wait between retry attempts (default: 20)",
				ValidateFunc: validation.IntAtLeast(1),
			},
			"status_code": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "HTTP status code from the response",
			},
			"workflow_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the workflow",
			},
			"workflow_status": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Current status of the workflow (In Progress, Success, Failed)",
			},
			"workflow_status_code": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Status code of the workflow (0=InProgress, 1=Success, others=Failed)",
			},
			"log_data": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "JSON string containing all tasks and logs",
			},
			"task_summary": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Summary of all task statuses",
			},
			"failed_task_logs": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Detailed logs of any failed tasks",
			},
			"failure_reason": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Extracted failure reason from failed task logs",
			},
			"response_message": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Summary response message from the workflow",
			},
			"success": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the workflow completed successfully",
			},
			"completed": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether the workflow has completed (success or failure)",
			},
			"created_by": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "User who created the workflow request",
			},
			"created_time": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Timestamp when the workflow request was created",
			},
			"completion_time": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Timestamp when the workflow completed or polling ended",
			},
			"last_polled_time": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Last time the status was polled",
			},
			"is_download_required": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether to download the certificate after workflow completion",
			},
			"certificate_download_path": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to download the certificate to",
			},
			"certificate_download_format": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "CRT",
				// ForceNew:    true,
				Description: "Format for the downloaded certificate (e.g., CRT, PFX)",
			},
			"certificate_chain_required": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
				// ForceNew:    true,
				Description: "Whether to include the certificate chain in the download",
			},
			"downloaded_certificate_path": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Full path to the downloaded certificate file",
			},
			"certificate_common_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Common name of the certificate",
			},
			"certificate_serial_number": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Serial number of the certificate",
			},
			// Resource Identifiers
			"certificate_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Unique identifier of the certificate in the CMS system",
			},
			"certificate_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Logical name of the certificate",
			},
			"key_vault_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Azure Key Vault resource ID where the certificate is stored",
			},
			"key_vault_secret_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the secret in Azure Key Vault",
			},
			// Certificate Metadata
			"subject_alternative_names": {
				Type:        schema.TypeList,
				Computed:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "List of Subject Alternative Names (SANs)",
			},
			"validity_period": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate validity period duration",
			},
			"issuer": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate Authority or issuer name",
			},
			"certificate_status": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Current certificate status (e.g., issued, pending, revoked)",
			},
			// Timestamps
			"issued_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Timestamp when the certificate was issued",
			},
			"expires_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate expiry timestamp",
			},
			// Additional certificate details
			"key_algorithm": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Key algorithm and size (e.g., RSA 2048)",
			},
			"signature_algorithm": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Signature algorithm used",
			},
			"thumbprint": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate thumbprint",
			},
			"certificate_uuid": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate UUID in the system",
			},
			"certificate_authority": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate Authority name",
			},
			"key_usage": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate key usage",
			},
			"extended_key_usage": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate extended key usage",
			},
			"certificate_expiry_status": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate expiry status (e.g., Active, Revoked, Expired)",
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: resourceCertificateImport,
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(60 * time.Minute),
		},
	}
}

func createPushCertificateRequestStatusRead(d *schema.ResourceData, m interface{}) error {
	logger.Info(" **************** READ OPERATION - WORKFLOW LOGS ****************")

	return nil
}

func createPushCertificateRequestStatusDelete(d *schema.ResourceData, m interface{}) error {
	logger.Info(" **************** DELETE OPERATION FOR WORKFLOW LOGS **************** ")
	// Since this is a read-only resource, deletion just removes it from state
	d.SetId("")
	return nil
}

func createPushCertificateRequestStatusUpdate(d *schema.ResourceData, m interface{}) error {
	logger.Info(" **************** UPDATE OPERATION FOR WORKFLOW LOGS **************** ")
	// Since this is a read-only resource, update just removes it from state
	return nil
}

func createPushCertificateRequestStatusCreate(d *schema.ResourceData, m interface{}) error {
	logger.Info(" **************** CREATE OPERATION FOR WORKFLOW LOGS **************** ")
	configAppViewXEnvironment := m.(*config.AppViewXEnvironment)

	// d.Partial(true)

	// Get request ID and retry parameters
	requestID := d.Get("request_id").(string)

	if requestID == "" {
		logger.Info(" No request ID provided, skipping workflow status polling")

		// Set a placeholder ID
		d.SetId(fmt.Sprintf("revoke-workflow-log-skipped-%s", strconv.Itoa(rand.Int())))

		// Set default values for computed fields
		d.Set("workflow_status", "Skipped")
		d.Set("workflow_status_code", -1) // Special code for skipped
		d.Set("completed", true)
		d.Set("success", false)
		d.Set("response_message", "Workflow polling was skipped because no request ID was provided")
		d.Set("last_polled_time", time.Now().Format(time.RFC3339))
		d.Set("completion_time", time.Now().Format(time.RFC3339))

		return nil
	}

	retryCount := d.Get("retry_count").(int)
	retryInterval := d.Get("retry_interval").(int)

	logger.Info(" Starting polling for workflow request ID: %s (max %d retries, %d second intervals)",
		requestID, retryCount, retryInterval)

	// Set resource ID early to ensure it's set even if polling fails
	d.SetId(fmt.Sprintf("workflow-log-%s-%s", requestID, strconv.Itoa(rand.Int())))

	// Authentication credentials
	appviewxUserName := configAppViewXEnvironment.AppViewXUserName
	appviewxPassword := configAppViewXEnvironment.AppViewXPassword
	appviewxClientId := configAppViewXEnvironment.AppViewXClientId
	appviewxClientSecret := configAppViewXEnvironment.AppViewXClientSecret
	appviewxEnvironmentIP := configAppViewXEnvironment.AppViewXEnvironmentIP
	appviewxEnvironmentPort := configAppViewXEnvironment.AppViewXEnvironmentPort
	appviewxEnvironmentIsHTTPS := configAppViewXEnvironment.AppViewXIsHTTPS
	appviewxGwSource := "external"

	// Keep track of completion
	var completed bool = false
	var finalStatusCode int = STATUS_IN_PROGRESS
	var lastResponse map[string]interface{}

	// Start polling
	for attempt := 1; attempt <= retryCount; attempt++ {
		logger.Info(" Polling attempt %d/%d for workflow request ID: %s", attempt, retryCount, requestID)

		// Get authentication token for this request
		appviewxSessionID, accessToken, err := authenticate(
			appviewxUserName, appviewxPassword,
			appviewxClientId, appviewxClientSecret,
			appviewxEnvironmentIP, appviewxEnvironmentPort,
			appviewxEnvironmentIsHTTPS)

		if err != nil {
			logger.Error(" Authentication failed on polling attempt %d: %v", attempt, err)
			// If we're on the last attempt, return the error
			if attempt == retryCount {
				return err
			}
			// Otherwise, try again after delay
			time.Sleep(time.Duration(retryInterval) * time.Second)
			continue
		}

		// Poll the workflow status
		statusCode, respBody, err := pollWorkflowStatus(
			appviewxEnvironmentIP, appviewxEnvironmentPort,
			appviewxEnvironmentIsHTTPS, appviewxSessionID,
			accessToken, requestID, appviewxGwSource)

		if err != nil {
			logger.Error(" Failed to poll workflow status on attempt %d: %v", attempt, err)
			// If we're on the last attempt, return the error
			if attempt == retryCount {
				return err
			}
			// Otherwise, try again after delay
			time.Sleep(time.Duration(retryInterval) * time.Second)
			continue
		}

		// Parse the response
		var responseObj map[string]interface{}
		if err := json.Unmarshal(respBody, &responseObj); err != nil {
			logger.Error(" Failed to parse response JSON on attempt %d: %v", attempt, err)
			if attempt == retryCount {
				return err
			}
			time.Sleep(time.Duration(retryInterval) * time.Second)
			continue
		}

		// Store the last response
		lastResponse = responseObj

		// Record last polled time
		d.Set("last_polled_time", time.Now().Format(time.RFC3339))

		// Check if the workflow has completed
		statusCode, completed = getWorkflowStatusCode(responseObj)
		finalStatusCode = statusCode

		// If workflow has completed (success or failure), break out of the loop
		if completed {
			logger.Info(" Workflow completed with status code %d after %d polling attempts",
				statusCode, attempt)
			break
		}

		// If we're not done yet and not on the last attempt, wait before trying again
		if attempt < retryCount {
			logger.Info(" Workflow Request ID: %s is in progress (status code: %d). Waiting %d seconds before next poll...",
				requestID, statusCode, retryInterval)
			time.Sleep(time.Duration(retryInterval) * time.Second)
		}
	}

	// Record completion time
	d.Set("completion_time", time.Now().Format(time.RFC3339))

	// If we've exhausted retries and workflow is still not complete
	if !completed {
		logger.Warn("Maximum retry count (%d) reached, but workflow is still in progress", retryCount)

		// Set timeout-related state information
		d.Set("workflow_status", "Timeout")
		d.Set("workflow_status_code", finalStatusCode)
		d.Set("completed", false)
		d.Set("success", false)
		d.Set("failure_reason", fmt.Sprintf("Polling timed out after %d attempts", retryCount))
		d.Set("response_message", fmt.Sprintf("Polling timed out before workflow completion after %d retry attempts", retryCount))
	}

	// Process and store the final response data
	if lastResponse != nil {
		processWorkflowResponse(d, m, lastResponse, finalStatusCode, completed)
	} else {
		// Set state for no response scenario
		d.Set("workflow_status", "No Response")
		d.Set("completed", false)
		d.Set("success", false)
		d.Set("failure_reason", fmt.Sprintf("No valid response received after %d attempts", retryCount))
		d.Set("response_message", fmt.Sprintf("No valid response received after %d polling attempts", retryCount))

		return fmt.Errorf("no valid response received after %d attempts", retryCount)
	}

	// Throw error after processing only if workflow actually failed (not timeout)
	if finalStatusCode != STATUS_SUCCESS && completed {
		failureReason := ""
		if reason, ok := d.GetOk("failure_reason"); ok && reason.(string) != "" {
			failureReason = reason.(string)
		}

		if failureReason != "" && failureReason != "No specific failure reason found in logs" {
			return fmt.Errorf("certificate workflow failed with status code %d: %s", finalStatusCode, failureReason)
		} else {
			return fmt.Errorf("certificate workflow failed with status code %d", finalStatusCode)
		}
	}

	// For timeout scenarios, don't throw error - just log and store state information
	// The workflow is still in progress on AppViewX side, it's not an actual failure
	if !completed {
		logger.Info("Workflow polling completed - workflow is still in progress on AppViewX (timeout after %d attempts)", retryCount)
	}

	return createPushCertificateRequestStatusRead(d, m)
}

func authenticate(username, password, clientId, clientSecret, envIP, envPort string, isHTTPS bool) (string, string, error) {
	var sessionID, accessToken string
	var err error

	// Try username/password authentication
	if username != "" && password != "" {
		sessionID, err = GetSession(username, password, envIP, envPort, "WEB", isHTTPS)
		if err != nil {
			logger.Info(" Session authentication failed, trying client credentials")
		} else {
			return sessionID, "", nil
		}
	}

	// If username/password failed or wasn't provided, try client ID/secret
	if sessionID == "" && clientId != "" && clientSecret != "" {
		accessToken, err = GetAccessToken(clientId, clientSecret, envIP, envPort, "WEB", isHTTPS)
		if err != nil {
			logger.Error(" Client credentials authentication failed")
			return "", "", err
		}
		return "", accessToken, nil
	}

	// If both authentication methods failed
	if sessionID == "" && accessToken == "" {
		return "", "", errors.New("authentication failed - provide either username/password or client ID/secret in Terraform File or in the Environment Variables:[APPVIEWX_TERRAFORM_CLIENT_ID, APPVIEWX_TERRAFORM_CLIENT_SECRET]")
	}

	return sessionID, accessToken, nil
}

func pollWorkflowStatus(envIP, envPort string, isHTTPS bool, sessionID, accessToken, requestID, gwSource string) (int, []byte, error) {
	// Set query parameters
	queryParams := map[string]string{
		"gwsource": gwSource,
		"ids":      requestID,
	}

	// Get URL for visualworkflow-request-logs
	url := GetURL(envIP, envPort, "visualworkflow-request-logs", queryParams, isHTTPS)
	logger.Debug(" 🌐 Fetching workflow request details using URL: %s", url)

	// Create HTTP client
	client := &http.Client{Transport: HTTPTransport()}

	// Create request
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("error creating HTTP request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Add authentication header
	if sessionID != "" {
		req.Header.Set(constants.SESSION_ID, sessionID)
	} else if accessToken != "" {
		req.Header.Set(constants.TOKEN, accessToken)
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("error making HTTP request: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("error reading response body: %v", err)
	}

	return resp.StatusCode, body, nil
}

func getWorkflowStatusCode(responseObj map[string]interface{}) (int, bool) {
	// Extract workflow status code from response
	if resp, ok := responseObj["response"].(map[string]interface{}); ok {
		if requestList, ok := resp["requestList"].([]interface{}); ok && len(requestList) > 0 {
			if firstRequest, ok := requestList[0].(map[string]interface{}); ok {
				if statusCode, ok := firstRequest["statusCode"].(float64); ok {
					intStatusCode := int(statusCode)

					// Check if completed based on status code
					if intStatusCode == STATUS_SUCCESS {
						return intStatusCode, true // Success, completed
					}

					// Check if failed (any of the failure codes)
					for _, failCode := range failedStatusCodes {
						if intStatusCode == failCode {
							return intStatusCode, true // Failed, but completed
						}
					}

					// If we get here, it's still in progress
					return intStatusCode, false
				}
			}
		}
	}

	// Default to in-progress if we can't determine status
	return STATUS_IN_PROGRESS, false
}

func processWorkflowResponse(d *schema.ResourceData, m interface{}, responseObj map[string]interface{}, statusCode int, completed bool) {
	// Store the full response JSON
	// prettyJSON, _ := json.MarshalIndent(responseObj, "", "  ")
	// d.Set("log_data", string(prettyJSON))
	d.Set("status_code", statusCode)
	d.Set("workflow_status_code", statusCode)
	d.Set("completed", completed)

	// Define variables for response messages
	var responseMessage, failureReason string

	// Process response data
	if resp, ok := responseObj["response"].(map[string]interface{}); ok {
		if requestList, ok := resp["requestList"].([]interface{}); ok && len(requestList) > 0 {
			if firstRequest, ok := requestList[0].(map[string]interface{}); ok {
				// Extract workflow details
				if workflowName, ok := firstRequest["workflowName"].(string); ok {
					d.Set("workflow_name", workflowName)
				}

				if status, ok := firstRequest["status"].(string); ok {
					d.Set("workflow_status", status)
					logger.Info(" Workflow status: %s (code: %d)", status, statusCode)
				}

				if createdBy, ok := firstRequest["created_by"].(string); ok {
					d.Set("created_by", createdBy)
				}

				if createdTime, ok := firstRequest["created_time"].(float64); ok {
					// Convert Unix timestamp to readable format
					t := time.Unix(int64(createdTime)/1000, 0)
					d.Set("created_time", t.Format(time.RFC3339))
				}

				// Set success flag based on status code
				isSuccess := statusCode == STATUS_SUCCESS
				d.Set("success", isSuccess)
				// logger.Info(" Workflow success: %t (completed: %t)", isSuccess, completed)

				// Pretty logging for success or failure
				requestId := d.Get("request_id").(string)
				commonName := d.Get("certificate_common_name").(string)

				if isSuccess {
					// Create a success summary in JSON format
					successData := map[string]interface{}{
						"operation":    "Certificate Creation and Push",
						"status":       "Successful",
						"workflow_id":  requestId,
						"status_code":  statusCode,
						"completed_at": time.Now().Format(time.RFC3339),
					}

					if commonName != "" {
						successData["certificate_common_name"] = commonName
					}
					var resourceId string
					// Process tasks to extract certificate resource ID if needed
					if tasks, ok := firstRequest["tasks"].([]interface{}); ok {
						// Log how many tasks we found
						logger.Debug(" Found %d tasks in workflow response", len(tasks))

						// Extract certificate resource ID if workflow succeeded
						resourceId = extractCertificateResourceId(tasks)
						if resourceId != "" {
							// d.Set("certificate_resource_id", resourceId)
							logger.Info(" Saved certificate resource ID to state: %s", resourceId)

							// Fetch certificate details and log comprehensive certificate information
							fetchAndLogCertificateDetails(resourceId, commonName, d, m)
						}
					}

					// Check if certificate download is required and handle it
					if d.Get("is_download_required").(bool) {
						logger.Info(" Certificate download is required, initiating download...")
						// Call the download function with the necessary parameters
						downloadCertificateIfRequired(resourceId, d, m, true)

						// resourceId := d.Get("certificate_resource_id").(string)
						successData["resource_id"] = resourceId

						certificateDownloadPath := d.Get("certificate_download_path").(string)
						successData["certificate_download_path"] = certificateDownloadPath

					} else {
						logger.Info(" Certificate download not requested (is_download_required=false)")
					}
					successJSON, _ := json.MarshalIndent(successData, "", "  ")
					successMessage := fmt.Sprintf("\n[CERTIFICATE CREATION][SUCCESS] ✅ Operation Result:\n%s\n", string(successJSON))
					logger.Info(successMessage)
				} else if completed {
					// Create a failure summary for completed but failed workflows
					failureData := map[string]interface{}{
						"operation":    "Certificate Creation and Push",
						"status":       "Failed",
						"workflow_id":  requestId,
						"status_code":  statusCode,
						"completed_at": time.Now().Format(time.RFC3339),
					}

					// Add certificate common name if available
					if commonName != "" {
						failureData["certificate_common_name"] = commonName
					}

					// Process tasks and extract failure information
					var taskSummary, failedTasksLog string
					failureReason = ""

					if tasks, ok := firstRequest["tasks"].([]interface{}); ok {
						taskSummary, failedTasksLog, failureReason = processTasks(tasks, isSuccess)
						d.Set("task_summary", taskSummary)
						d.Set("failed_task_logs", failedTasksLog)

						if failureReason != "" && failureReason != "No specific failure reason found in logs" {
							failureData["failure_reason"] = failureReason
						} else {
							// Try to find failure info directly in the workflow response
							if message, ok := firstRequest["message"].(string); ok && message != "" {
								if containsAny(message, []string{"Failed", "Error", "failed", "error"}) {
									failureReason = message
									failureData["failure_reason"] = failureReason
								}
							}

							// If still no reason, check if there's a tooltip
							if tooltip, ok := firstRequest["toolTip"].(string); ok && tooltip != "" {
								failureReason = tooltip
								failureData["failure_reason"] = failureReason
							}
						}
					}

					failureJSON, _ := json.MarshalIndent(failureData, "", "  ")
					failureMessage := fmt.Sprintf("\n[CERTIFICATE CREATION AND PUSH TO AKV][FAILURE] ❌ Operation Result:\n%s\n", string(failureJSON))
					logger.Error(failureMessage)
				} else {
					// For incomplete operations (timed out)
					timeoutData := map[string]interface{}{
						"operation":      "Certificate Creation and Push",
						"status":         "Timeout",
						"workflow_id":    requestId,
						"status_code":    statusCode,
						"completed":      false,
						"message":        "Polling timed out before workflow completion",
						"last_polled_at": time.Now().Format(time.RFC3339),
					}

					// Add certificate common name if available
					if commonName != "" {
						timeoutData["certificate_common_name"] = commonName
					}

					timeoutJSON, _ := json.MarshalIndent(timeoutData, "", "  ")
					timeoutMessage := fmt.Sprintf("\n[CERTIFICATE CREATION][TIMEOUT] ⏱️ Operation Result:\n%s\n", string(timeoutJSON))
					logger.Info(timeoutMessage)
				}
			}
		}
	}

	// Add the failure reason to the response message if it exists
	if failureReason != "" && failureReason != "No specific failure reason found in logs" {
		logger.Info(" Failure reason: %s", failureReason)
	}

	// Set the response message and failure reason
	d.Set("response_message", responseMessage)
	d.Set("failure_reason", failureReason)
}

func buildResponseMessage(requestData map[string]interface{}, statusCode int, failureReason string) string {
	var message bytes.Buffer

	// Extract basic workflow info
	workflowName, _ := requestData["workflowName"].(string)
	requestId, _ := requestData["requestId"].(string)
	status, _ := requestData["status"].(string)

	// Format the message as JSON
	responseData := map[string]interface{}{
		"workflow_name": workflowName,
		"request_id":    requestId,
		"status":        status,
		"status_code":   statusCode,
		"completed":     statusCode != STATUS_IN_PROGRESS,
		"successful":    statusCode == STATUS_SUCCESS,
		"timestamp":     time.Now().Format(time.RFC3339),
	}

	// If there's a failure, add error information
	if statusCode != STATUS_IN_PROGRESS && statusCode != STATUS_SUCCESS {
		responseData["error"] = "Workflow execution failed"

		// Add the failure reason if we have one
		if failureReason != "" && failureReason != "No specific failure reason found in logs" {
			responseData["failure_reason"] = failureReason
		}
	}

	// Create pretty JSON
	prettyJSON, err := json.MarshalIndent(responseData, "", "  ")
	if err != nil {
		message.WriteString(fmt.Sprintf("Error creating response message: %v", err))
	} else {
		message.WriteString(string(prettyJSON))
	}

	return message.String()
}

// Update the extractFailureReason function with a simpler approach
func extractFailureReason(logs []interface{}) string {
	// If there are no logs, we can't extract a failure reason
	if len(logs) == 0 {
		return "No logs found to determine failure reason"
	}

	// Special case: If second-to-last log entry contains "Request Failed.Please check the Request ID",
	// then use the third-to-last entry which typically contains the detailed error
	if len(logs) >= 3 {
		// Check second-to-last entry for reference to another request ID
		if secondToLast, ok := logs[len(logs)-2].(map[string]interface{}); ok {
			secondToLastMsg := getStringValue(secondToLast, "message")
			if strings.Contains(secondToLastMsg, "Request Failed.Please check the Request ID") {
				logger.Debug("Found reference to another request ID in logs, checking third-to-last message for details")

				// Get the third-to-last log entry which should contain the actual error
				if thirdToLast, ok := logs[len(logs)-3].(map[string]interface{}); ok {
					thirdToLastMsg := getStringValue(thirdToLast, "message")
					if thirdToLastMsg != "" {
						// Return the third-to-last message directly without parsing
						return thirdToLastMsg
					}
				}
			}
		}
	}

	// Original logic for other cases
	// Try second-to-last entry first
	var relevantLog map[string]interface{}

	if len(logs) >= 2 {
		if logEntry, ok := logs[len(logs)-2].(map[string]interface{}); ok {
			relevantLog = logEntry
		}
	}

	// If we couldn't get the second-to-last, try the last one
	if relevantLog == nil && len(logs) > 0 {
		if logEntry, ok := logs[len(logs)-1].(map[string]interface{}); ok {
			relevantLog = logEntry
		}
	}

	// If we found a relevant log entry, extract the message
	if relevantLog != nil {
		if message, ok := relevantLog["message"].(string); ok && message != "" {
			return message
		}
	}

	return "No specific failure reason found in logs"
}

// Update the processTasks function to focus on the actual failure message
func processTasks(tasks []interface{}, isSuccess bool) (string, string, string) {
	var taskSummary bytes.Buffer
	var failedTaskLogs bytes.Buffer
	var failureReason string

	taskSummary.WriteString("Task Status Summary:\n")
	taskSummary.WriteString("-------------------\n")

	// First find any failed tasks
	var failedTasks []map[string]interface{}

	for _, t := range tasks {
		task, ok := t.(map[string]interface{})
		if !ok {
			continue
		}

		taskState := getIntValue(task, "state")
		taskName := getStringValue(task, "task_name")
		taskStatus := getStringValue(task, "task_status")

		// Add to summary regardless of status
		taskSummary.WriteString(fmt.Sprintf("- %s: %s (State: %d)\n", taskName, taskStatus, taskState))

		if isFailedState(taskState) {
			failedTasks = append(failedTasks, task)
		}
	}

	// If we found failed tasks, focus on them
	if len(failedTasks) > 0 {
		logger.Info(" Found %d failed tasks in workflow", len(failedTasks))

		// Get the first failed task for the primary error message
		failedTask := failedTasks[0]
		taskName := getStringValue(failedTask, "task_name")
		taskStatus := getStringValue(failedTask, "task_status")

		failedTaskLogs.WriteString(fmt.Sprintf("\n== FAILED TASK: %s ==\n", taskName))
		failedTaskLogs.WriteString(fmt.Sprintf("Status: %s\n\n", taskStatus))

		// Extract logs for the failed task
		if logs, ok := failedTask["logs"].([]interface{}); ok {
			failedTaskLogs.WriteString("Logs:\n")

			// Get the failure reason from the logs
			failureReason = extractFailureReason(logs)

			// Log all messages for this failed task
			for _, l := range logs {
				logEntry, ok := l.(map[string]interface{})
				if !ok {
					continue
				}

				user := getStringValue(logEntry, "user")
				message := getStringValue(logEntry, "message")
				timestamp := getFloatValue(logEntry, "time")

				// Format the log entry
				timeStr := ""
				if timestamp > 0 {
					t := time.Unix(int64(timestamp)/1000, 0)
					timeStr = t.Format(time.RFC3339)
				}

				failedTaskLogs.WriteString(fmt.Sprintf("[%s] %s: %s\n", timeStr, user, message))
			}
		}
	}

	return taskSummary.String(), failedTaskLogs.String(), failureReason
}

// Helper function to check if a string contains any of the given substrings
func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// Helper functions for getting values from maps
func getStringValue(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func getIntValue(m map[string]interface{}, key string) int {
	if val, ok := m[key].(float64); ok {
		return int(val)
	}
	return 0
}

func getFloatValue(m map[string]interface{}, key string) float64 {
	if val, ok := m[key].(float64); ok {
		return val
	}
	return 0
}

func isFailedState(state int) bool {
	// Check if the state indicates failure
	for _, failedState := range failedStatusCodes {
		if state == failedState {
			return true
		}
	}
	return false
}

func extractCertificateResourceId(tasks []interface{}) string {
	// Look for the specific task
	for _, t := range tasks {
		task, ok := t.(map[string]interface{})
		if !ok {
			continue
		}

		taskName := getStringValue(task, "task_name")
		taskStatus := getStringValue(task, "task_status")

		// Check if this is the "Trigger Certificate Creation" task and it succeeded
		if taskName == "Trigger Certificate Creation" && taskStatus == "Success" {
			// Extract logs to find the resource ID
			if logs, ok := task["logs"].([]interface{}); ok {
				// Try different extraction strategies

				// Strategy 1: Look for JSON string containing resourceId
				for _, l := range logs {
					logEntry, ok := l.(map[string]interface{})
					if !ok {
						continue
					}

					message := getStringValue(logEntry, "message")

					// Skip empty messages
					if message == "" {
						continue
					}

					// Look for JSON response containing resourceId
					if strings.Contains(message, "resourceId") {
						logger.Debug(" Found message containing resourceId: %s", message)

						// Strategy 1.1: Extract using regex for Python dict format
						reDict := regexp.MustCompile(`'resourceId':\s*'([^']+)'`)
						matches := reDict.FindStringSubmatch(message)
						if len(matches) > 1 {
							logger.Info(" Extracted certificate resource ID (Python dict): %s", matches[1])
							return matches[1]
						}

						// Strategy 1.2: Extract using regex for JSON format
						reJson := regexp.MustCompile(`"resourceId":\s*"([^"]+)"`)
						matches = reJson.FindStringSubmatch(message)
						if len(matches) > 1 {
							logger.Info(" Extracted certificate resource ID (JSON): %s", matches[1])
							return matches[1]
						}

						// Strategy 1.3: Try to parse the JSON string
						if strings.Contains(message, "{") && strings.Contains(message, "}") {
							jsonStart := strings.Index(message, "{")
							jsonEnd := strings.LastIndex(message, "}") + 1

							if jsonStart >= 0 && jsonEnd > jsonStart {
								jsonStr := message[jsonStart:jsonEnd]

								var jsonData map[string]interface{}
								if err := json.Unmarshal([]byte(jsonStr), &jsonData); err == nil {
									if resp, ok := jsonData["response"].(map[string]interface{}); ok {
										if resourceId, ok := resp["resourceId"].(string); ok && resourceId != "" {
											logger.Info(" Extracted certificate resource ID (JSON parse): %s", resourceId)
											return resourceId
										}
									}
								} else {
									logger.Debug(" Failed to parse JSON: %v", err)
								}
							}
						}
					}
				}

				// Strategy 2: Look for specific log messages about resource creation
				for _, l := range logs {
					logEntry, ok := l.(map[string]interface{})
					if !ok {
						continue
					}

					message := getStringValue(logEntry, "message")

					// Look for resource creation messages
					if strings.Contains(message, "Certificate created with resource ID") {
						re := regexp.MustCompile(`Certificate created with resource ID[:\s]+([a-zA-Z0-9]+)`)
						matches := re.FindStringSubmatch(message)
						if len(matches) > 1 {
							logger.Info(" Extracted certificate resource ID from creation message: %s", matches[1])
							return matches[1]
						}
					}
				}
			}
		}
	}

	// If we didn't find the specific task, look in all tasks as a fallback
	for _, t := range tasks {
		task, ok := t.(map[string]interface{})
		if !ok {
			continue
		}

		if logs, ok := task["logs"].([]interface{}); ok {
			for _, l := range logs {
				logEntry, ok := l.(map[string]interface{})
				if !ok {
					continue
				}

				message := getStringValue(logEntry, "message")

				// Skip empty messages
				if message == "" {
					continue
				}

				// Look for resourceId in any log message
				if strings.Contains(message, "resourceId") {
					logger.Debug(" Found message containing resourceId in task %s: %s",
						getStringValue(task, "task_name"), message)

					// Try regex extraction
					re := regexp.MustCompile(`['"](resourceId)['"]:\s*['"]([^'"]+)['"]`)
					matches := re.FindStringSubmatch(message)
					if len(matches) > 2 {
						logger.Info(" Extracted certificate resource ID from general logs: %s", matches[2])
						return matches[2]
					}
				}
			}
		}
	}

	logger.Info(" No certificate resource ID found in workflow logs")
	return ""
}

// Add this function to your resource_workflow_logs.go file

// fetchCertificateDetails retrieves certificate details using the resource ID and populates terraform state
func fetchCertificateDetails(resourceId, certType, appviewxSessionID, accessToken string, configAppViewXEnvironment *config.AppViewXEnvironment, d *schema.ResourceData) error {
	logger.Info(" Fetching certificate details for resource ID: %s", resourceId)

	// Extract configuration parameters
	appviewxEnvironmentIP := configAppViewXEnvironment.AppViewXEnvironmentIP
	appviewxEnvironmentPort := configAppViewXEnvironment.AppViewXEnvironmentPort
	appviewxEnvironmentIsHTTPS := configAppViewXEnvironment.AppViewXIsHTTPS

	// Set query parameters
	queryParams := map[string]string{
		"gwsource": "external",
	}

	// Get URL for the certificate search endpoint
	url := GetURL(appviewxEnvironmentIP, appviewxEnvironmentPort, "certificate/search", queryParams, appviewxEnvironmentIsHTTPS)
	logger.Info("Certificate Type :::::::::::::::::::::::::::::::: %s", certType)
	// Build search payload
	payload := map[string]interface{}{
		"input": map[string]interface{}{
			"resourceId": resourceId,
			"category":   certType,
		},
		"filter": map[string]interface{}{
			"start": 1,
			"max":   1,
		},
	}

	// Prepare the request
	requestBody, err := json.Marshal(payload)
	if err != nil {
		logger.Error(" Error marshalling certificate search payload: %v", err)
		return err
	}

	// Create HTTP client
	client := &http.Client{Transport: HTTPTransport()}

	// Create request
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(requestBody))
	if err != nil {
		logger.Error(" Error creating certificate search request: %v", err)
		return err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Add authentication header
	if appviewxSessionID != "" {
		req.Header.Set(constants.SESSION_ID, appviewxSessionID)
	} else if accessToken != "" {
		req.Header.Set(constants.TOKEN, accessToken)
	}

	logger.Debug(" Sending certificate search request to: %s", url)

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		logger.Error(" Error making certificate search request: %v", err)
		return err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error(" Error reading certificate search response: %v", err)
		return err
	}

	// Format and log JSON response for debugging
	// var prettyJSON bytes.Buffer
	// if json.Indent(&prettyJSON, body, "", "  ") == nil {
	// 	logger.Info(" Certificate search response body (formatted JSON):\n%s", prettyJSON.String())
	// } else {
	// 	logger.Info(" Certificate search response body (raw):\n%s", string(body))
	// }

	// Log the full response for debugging
	logger.Info(" Certificate search response status: %d", resp.StatusCode)
	// logger.Info(" Certificate search full response:\n%s", string(body))

	// Parse response to extract certificate details
	var responseObj map[string]interface{}
	if err := json.Unmarshal(body, &responseObj); err != nil {
		logger.Error(" Error parsing certificate search response: %v", err)
		return err
	}

	// Extract and populate all certificate details from response
	if resp, ok := responseObj["response"].(map[string]interface{}); ok {
		if innerResp, ok := resp["response"].(map[string]interface{}); ok {
			if objects, ok := innerResp["objects"].([]interface{}); ok && len(objects) > 0 {
				if cert, ok := objects[0].(map[string]interface{}); ok {
					logger.Info(" Successfully found certificate object, extracting details...")

					// Basic certificate information
					if cn, ok := cert["commonName"].(string); ok {
						d.Set("certificate_common_name", cn)
						logger.Info(" Set certificate_common_name: %s", cn)
					}

					if sn, ok := cert["serialNumber"].(string); ok {
						d.Set("certificate_serial_number", sn)
						logger.Info(" Set certificate_serial_number: %s", sn)
					}

					// Resource Identifiers
					if uuid, ok := cert["uuid"].(string); ok {
						d.Set("certificate_uuid", uuid)
						d.Set("certificate_id", uuid) // Using UUID as certificate ID
						logger.Info(" Set certificate_uuid: %s", uuid)
					}

					if resourceIdFromResp, ok := cert["resourceId"].(string); ok {
						d.Set("certificate_name", resourceIdFromResp)
						logger.Info(" Set certificate_name: %s", resourceIdFromResp)
					}

					// Extract Azure Key Vault information from device details
					if deviceDetails, ok := cert["deviceDetails"].(map[string]interface{}); ok {
						if attributes, ok := deviceDetails["attributes"].(map[string]interface{}); ok {
							if keyVaultName, ok := attributes["keyVaultName"].(string); ok {
								d.Set("key_vault_id", keyVaultName)
								logger.Info(" Set key_vault_id: %s", keyVaultName)
							}
							if certFileName, ok := attributes["certificateFileName"].(string); ok {
								d.Set("key_vault_secret_name", certFileName)
								logger.Info(" Set key_vault_secret_name: %s", certFileName)
							}
						}
					}

					// Certificate Metadata
					if sans, ok := cert["subjectAlternativeNames"].([]interface{}); ok {
						sanList := make([]string, len(sans))
						for i, san := range sans {
							if sanStr, ok := san.(string); ok {
								sanList[i] = sanStr
							}
						}
						d.Set("subject_alternative_names", sanList)
						logger.Info(" Set subject_alternative_names: %v", sanList)
					}

					if validFor, ok := cert["validFor"].(string); ok {
						d.Set("validity_period", validFor)
						logger.Info(" Set validity_period: %s", validFor)
					}

					if issuer, ok := cert["issuerCommonName"].(string); ok {
						d.Set("issuer", issuer)
						logger.Info(" Set issuer: %s", issuer)
					}

					if status, ok := cert["status"].(string); ok {
						d.Set("certificate_status", status)
						logger.Info(" Set certificate_status: %s", status)
					}

					// Timestamps
					if validFrom, ok := cert["validFrom"].(float64); ok {
						issuedAt := time.Unix(int64(validFrom)/1000, 0).Format(time.RFC3339)
						d.Set("issued_at", issuedAt)
						logger.Info(" Set issued_at: %s", issuedAt)
					}

					if validTo, ok := cert["validTo"].(float64); ok {
						expiresAt := time.Unix(int64(validTo)/1000, 0).Format(time.RFC3339)
						d.Set("expires_at", expiresAt)
						logger.Info(" Set expires_at: %s", expiresAt)
					}

					// Additional certificate details
					if keyAlgo, ok := cert["keyAlgorithmAndSize"].(string); ok {
						d.Set("key_algorithm", keyAlgo)
						logger.Info(" Set key_algorithm: %s", keyAlgo)
					}

					if sigAlgo, ok := cert["signatureAlgorithm"].(string); ok {
						d.Set("signature_algorithm", sigAlgo)
						logger.Info(" Set signature_algorithm: %s", sigAlgo)
					}

					if thumbprint, ok := cert["thumbPrint"].(string); ok {
						d.Set("thumbprint", thumbprint)
						logger.Info(" Set thumbprint: %s", thumbprint)
					}

					if ca, ok := cert["certificateAuthority"].(string); ok {
						d.Set("certificate_authority", ca)
						logger.Info(" Set certificate_authority: %s", ca)
					}

					if keyUsage, ok := cert["keyUsage"].(string); ok {
						d.Set("key_usage", keyUsage)
						logger.Info(" Set key_usage: %s", keyUsage)
					}

					if extKeyUsage, ok := cert["extendedKeyUsage"].(string); ok {
						d.Set("extended_key_usage", extKeyUsage)
						logger.Info(" Set extended_key_usage: %s", extKeyUsage)
					}

					if expiryStatus, ok := cert["expiryStatus"].(string); ok {
						d.Set("certificate_expiry_status", expiryStatus)
						logger.Info(" Set certificate_expiry_status: %s", expiryStatus)
					}

					logger.Info(" Successfully populated all certificate details in terraform state")
					return nil
				}
			}
		}
	}

	logger.Warn(" Could not extract certificate details from response")
	return fmt.Errorf("certificate details not found in response")
}

// downloadCertificateIfRequired handles certificate downloading if requested in configuration
func downloadCertificateIfRequired(resourceId string, d *schema.ResourceData, m interface{}, isSuccess bool) {
	// Only proceed if workflow succeeded and download is requested
	if !isSuccess || !d.Get("is_download_required").(bool) {
		return
	}

	// resourceId := d.Get("certificate_resource_id").(string)
	certCommonName := d.Get("certificate_common_name").(string)
	if certCommonName == "" {
		logger.Info(" Certificate Common Name not found in the Input, Proceeding with the Default Certificate Name")
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		certCommonName = "certificate-" + resourceId + "-" + timestamp
	}
	logger.Debug(" Certificate common name: %s", certCommonName)
	if resourceId == "" {
		logger.Warn("Cannot download certificate: No certificate resource ID found in workflow response")
		return
	}

	logger.Info(" Initiating certificate download for resource ID: %s", resourceId)

	// Get authentication tokens
	configAppViewXEnvironment := m.(*config.AppViewXEnvironment)
	appviewxUserName := configAppViewXEnvironment.AppViewXUserName
	appviewxPassword := configAppViewXEnvironment.AppViewXPassword
	appviewxClientId := configAppViewXEnvironment.AppViewXClientId
	appviewxClientSecret := configAppViewXEnvironment.AppViewXClientSecret
	appviewxEnvironmentIP := configAppViewXEnvironment.AppViewXEnvironmentIP
	appviewxEnvironmentPort := configAppViewXEnvironment.AppViewXEnvironmentPort
	appviewxEnvironmentIsHTTPS := configAppViewXEnvironment.AppViewXIsHTTPS

	var appviewxSessionID, accessToken string
	var err error

	// Use same authentication as the rest of the function
	if appviewxUserName != "" && appviewxPassword != "" {
		appviewxSessionID, err = GetSession(appviewxUserName, appviewxPassword, appviewxEnvironmentIP, appviewxEnvironmentPort, "WEB", appviewxEnvironmentIsHTTPS)
		if err != nil {
			logger.Error(" Error getting session for certificate download: %v", err)
			return
		}
	} else if appviewxClientId != "" && appviewxClientSecret != "" {
		accessToken, err = GetAccessToken(appviewxClientId, appviewxClientSecret, appviewxEnvironmentIP, appviewxEnvironmentPort, "WEB", appviewxEnvironmentIsHTTPS)
		if err != nil {
			logger.Error(" Error getting access token for certificate download: %v", err)
			return
		}
	}

	// Get download parameters
	downloadPath := d.Get("certificate_download_path").(string)
	downloadFormat := d.Get("certificate_download_format").(string)
	certificateChainRequired := d.Get("certificate_chain_required").(bool)

	if downloadPath == "" {
		logger.Warn("Cannot download certificate: No download path specified")
		return
	}

	// Prepare download path with certificate common name
	fullDownloadPath := downloadPath
	if !strings.HasSuffix(fullDownloadPath, "/") {
		fullDownloadPath += "/"
	}

	// Sanitize common name for filename
	safeCommonName := strings.ReplaceAll(certCommonName, "*", "wildcard")
	safeCommonName = strings.ReplaceAll(safeCommonName, ".", "_")
	safeCommonName = strings.ReplaceAll(safeCommonName, " ", "_")

	fullDownloadPath += safeCommonName + "." + strings.ToLower(downloadFormat)

	logger.Info(" Downloading certificate to: %s", fullDownloadPath)
	// Get certificate download password if required
	// certDownloadPassword := d.Get("certificate_download_password").(string)
	// Download certificate
	downloadSuccess := downloadCertificateFromAppviewx(
		resourceId,
		certCommonName,
		"",
		downloadFormat,
		"",
		fullDownloadPath,
		certificateChainRequired,
		appviewxSessionID,
		accessToken,
		configAppViewXEnvironment,
	)

	if downloadSuccess {
		logger.Info(" Certificate downloaded successfully to: %s", fullDownloadPath)
		d.Set("downloaded_certificate_path", fullDownloadPath)
	} else {
		logger.Error(" Failed to download certificate")
	}
}

// fetchAndLogCertificateDetails uses the existing fetchCertificateDetails method to get and log certificate information
func fetchAndLogCertificateDetails(resourceId, commonName string, d *schema.ResourceData, m interface{}) {
	logger.Info("\n=== SEARCHING FOR CERTIFICATE DETAILS ===")
	logger.Info(" Resource ID: %s", resourceId)
	logger.Info(" Common Name: %s", commonName)

	// Get configuration
	configAppViewXEnvironment := m.(*config.AppViewXEnvironment)

	// Get authentication credentials
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

	// Try authentication
	if appviewxUserName != "" && appviewxPassword != "" {
		appviewxSessionID, err = GetSession(appviewxUserName, appviewxPassword, appviewxEnvironmentIP, appviewxEnvironmentPort, appviewxGwSource, appviewxEnvironmentIsHTTPS)
		if err != nil {
			logger.Error("Failed to get session for certificate search: %v", err)
			return
		}
		logger.Info("Successfully authenticated using session ID")
	} else if appviewxClientId != "" && appviewxClientSecret != "" {
		accessToken, err = GetAccessToken(appviewxClientId, appviewxClientSecret, appviewxEnvironmentIP, appviewxEnvironmentPort, appviewxGwSource, appviewxEnvironmentIsHTTPS)
		if err != nil {
			logger.Error("Failed to get access token for certificate search: %v", err)
			return
		}
		logger.Info("Successfully authenticated using access token")
	} else {
		logger.Error("No authentication credentials available for certificate search")
		return
	}

	// Use the existing fetchCertificateDetails method
	logger.Info("Calling fetchCertificateDetails with:")
	logger.Info(" - Resource ID: %s", resourceId)
	logger.Info(" - Certificate Type: Server")
	logger.Info(" - Session ID: %s", appviewxSessionID)
	logger.Info(" - Access Token: %s", accessToken)

	err = fetchCertificateDetails(
		resourceId,
		"Server",
		appviewxSessionID,
		accessToken,
		configAppViewXEnvironment,
		d,
	)

	if err != nil {
		logger.Error("Failed to fetch certificate details using resourceId: %v", err)
		logger.Error("This error indicates the certificate search API may have issues")
		logger.Error("Common causes: invalid resourceId, authentication issues, or API endpoint problems")

		// Log the specific search parameters that failed
		logger.Error("Search parameters that failed:")
		logger.Error(" - Resource ID: %s", resourceId)
		logger.Error(" - Certificate Type: Server")
		logger.Error(" - Environment: %s:%s",
			configAppViewXEnvironment.AppViewXEnvironmentIP,
			configAppViewXEnvironment.AppViewXEnvironmentPort)
		logger.Error(" - HTTPS: %t", configAppViewXEnvironment.AppViewXIsHTTPS)
		logger.Error(" - Session ID provided: %t", appviewxSessionID != "")
		logger.Error(" - Access Token provided: %t", accessToken != "")

		return
	}

	// Log success - the details are already set in terraform state by fetchCertificateDetails
	logger.Info("\n=== CERTIFICATE SEARCH RESULTS ===")
	logger.Info("Certificate details successfully retrieved and populated in terraform state:")
	logger.Info(" Common Name: %s", d.Get("certificate_common_name").(string))
	logger.Info(" Serial Number: %s", d.Get("certificate_serial_number").(string))
	logger.Info(" Certificate UUID: %s", d.Get("certificate_uuid").(string))
	logger.Info(" Key Vault ID: %s", d.Get("key_vault_id").(string))
	logger.Info(" Key Vault Secret Name: %s", d.Get("key_vault_secret_name").(string))
	logger.Info(" Certificate Status: %s", d.Get("certificate_status").(string))
	logger.Info(" Issuer: %s", d.Get("issuer").(string))
	logger.Info(" Issued At: %s", d.Get("issued_at").(string))
	logger.Info(" Expires At: %s", d.Get("expires_at").(string))

	// Log SANs
	if sans := d.Get("subject_alternative_names").([]interface{}); len(sans) > 0 {
		logger.Info(" Subject Alternative Names: %v", sans)
	}

	logger.Info("=== CERTIFICATE SEARCH COMPLETED ===\n")
}
