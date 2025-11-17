package appviewx

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"terraform-provider-appviewx/appviewx/config"
	"terraform-provider-appviewx/appviewx/logger"
)

// Status code constants are defined in resource_create_push_certificate_request_status.go
// Failed status codes are defined in resource_create_push_certificate_request_status.go

func RevokeCertificateRequestStatus() *schema.Resource {
	return &schema.Resource{
		Create: revokeCertificateRequestStatusCreate,
		Read:   revokeCertificateRequestStatusRead,
		Delete: revokeCertificateRequestStatusDelete,
		Update: revokeCertificateRequestStatusUpdate,

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
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(60 * time.Minute),
		},
	}
}

func revokeCertificateRequestStatusRead(d *schema.ResourceData, m interface{}) error {
	logger.Info("**************** READ OPERATION - REVOKE CERTIFICATE WORKFLOW LOGS ****************")

	// Preserve all fields to avoid drift warnings
	schemaKeys := []string{
		"request_id", "retry_count", "retry_interval", "success", "workflow_status",
		"workflow_status_code", "task_summary", "failed_task_logs",
		"response_message", "failure_reason", "created_by", "created_time",
		"completion_time", "last_polled_time", "completed", "status_code",
		"workflow_name",
	}

	for _, key := range schemaKeys {
		if v, ok := d.GetOk(key); ok {
			d.Set(key, v)
		}
	}

	return nil
}

func revokeCertificateRequestStatusDelete(d *schema.ResourceData, m interface{}) error {
	logger.Info("**************** DELETE OPERATION FOR REVOKE CERTIFICATE WORKFLOW LOGS **************** ")
	// Since this is a read-only resource, deletion just removes it from state
	d.SetId("")
	return nil
}

func revokeCertificateRequestStatusUpdate(d *schema.ResourceData, m interface{}) error {
	logger.Info("**************** UPDATE OPERATION FOR REVOKE CERTIFICATE WORKFLOW LOGS **************** ")
	// Since this is a read-only resource, update just removes it from state
	return nil
}

func revokeCertificateRequestStatusCreate(d *schema.ResourceData, m interface{}) error {
	logger.Info("**************** CREATE OPERATION FOR REVOKE CERTIFICATE WORKFLOW LOGS **************** ")
	configAppViewXEnvironment := m.(*config.AppViewXEnvironment)

	// Get request ID and retry parameters
	requestID := d.Get("request_id").(string)

	if requestID == "" {
		logger.Info("No request ID provided, skipping workflow status polling")

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

	logger.Info(" Starting polling for revoke certificate workflow request ID: %s (max %d retries, %d second intervals)",
		requestID, retryCount, retryInterval)

	// Set resource ID early to ensure it's set even if polling fails
	d.SetId(fmt.Sprintf("revoke-workflow-log-%s-%s", requestID, strconv.Itoa(rand.Int())))

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
		logger.Info(" Polling attempt %d/%d for revoke workflow request ID: %s", attempt, retryCount, requestID)

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
			logger.Info(" Revoke workflow completed with status code %d after %d polling attempts",
				statusCode, attempt)
			break
		}

		// If we're not done yet and not on the last attempt, wait before trying again
		if attempt < retryCount {
			logger.Info(" Revoke Workflow Request is in progress %s (status code: %d). Waiting %d seconds before next poll...", requestID,
				statusCode, retryInterval)
			time.Sleep(time.Duration(retryInterval) * time.Second)
		}
	}

	// Record completion time
	d.Set("completion_time", time.Now().Format(time.RFC3339))

	// If we've exhausted retries and workflow is still not complete
	if !completed {
		logger.Warn(" Maximum retry count (%d) reached, but revoke workflow is still in progress", retryCount)

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
		processRevokeWorkflowResponse(d, lastResponse, finalStatusCode, completed)
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
			return fmt.Errorf("revoke certificate workflow failed with status code %d: %s", finalStatusCode, failureReason)
		} else {
			return fmt.Errorf("revoke certificate workflow failed with status code %d", finalStatusCode)
		}
	}

	// For timeout scenarios, don't throw error - just log and store state information
	// The workflow is still in progress on AppViewX side, it's not an actual failure
	if !completed {
		logger.Info("Revoke workflow polling completed - workflow is still in progress on AppViewX (timeout after %d attempts)", retryCount)
	}

	return revokeCertificateRequestStatusRead(d, m)
}

// processRevokeWorkflowResponse processes the workflow response specifically for certificate revocation
// This is a simplified version that doesn't include certificate download logic
func processRevokeWorkflowResponse(d *schema.ResourceData, responseObj map[string]interface{}, statusCode int, completed bool) {
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
					logger.Info(" Revoke workflow status: %s (code: %d)", status, statusCode)
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
				// logger.Info(" Revoke workflow success: %t (completed: %t)", isSuccess, completed)

				// Pretty logging for success or failure
				requestId := d.Get("request_id").(string)
				var taskSummary, failedTasksLog string
				failureReason = ""
				if isSuccess {
					// Create a success summary with safe handling of resource_id
					successData := map[string]interface{}{
						"operation":    "Certificate Revocation",
						"status":       "Successful",
						"workflow_id":  requestId,
						"status_code":  statusCode,
						"completed_at": time.Now().Format(time.RFC3339),
					}

					// Only add resource_id if it exists in the state
					if resourceId, ok := d.GetOk("resource_id"); ok {
						successData["resource_id"] = resourceId.(string)
					}

					successJSON, _ := json.MarshalIndent(successData, "", "  ")
					successMessage := fmt.Sprintf("\n[CERTIFICATE REVOCATION][SUCCESS] ✅ Operation Result:\n%s\n", string(successJSON))
					log.Println(successMessage)
				} else if completed {
					// Create a failure summary for completed but failed workflows
					failureData := map[string]interface{}{
						"operation":    "Certificate Revocation",
						"status":       "Failed",
						"workflow_id":  requestId,
						"status_code":  statusCode,
						"completed_at": time.Now().Format(time.RFC3339),
					}

					// Add failure reason if available
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
					failureMessage := fmt.Sprintf("\n[CERTIFICATE REVOCATION][FAILURE] ❌ Operation Result:\n%s\n", string(failureJSON))
					log.Println(failureMessage)
				} else {
					// For incomplete operations (timed out)
					timeoutData := map[string]interface{}{
						"operation":      "Certificate Revocation",
						"status":         "Timeout",
						"workflow_id":    requestId,
						"status_code":    statusCode,
						"completed":      false,
						"message":        "Polling timed out before workflow completion",
						"last_polled_at": time.Now().Format(time.RFC3339),
					}

					timeoutJSON, _ := json.MarshalIndent(timeoutData, "", "  ")
					timeoutMessage := fmt.Sprintf("\n[CERTIFICATE REVOCATION][TIMEOUT] ⏱️ Operation Result:\n%s\n", string(timeoutJSON))
					log.Println(timeoutMessage)
				}

				// Process tasks and extract failure information if needed - now just for state data

				if tasks, ok := firstRequest["tasks"].([]interface{}); ok {
					// Log how many tasks we found
					logger.Debug(" Found %d tasks in revoke workflow response", len(tasks))

					taskSummary, failedTasksLog, failureReason = processTasks(tasks, isSuccess)
					d.Set("task_summary", taskSummary)
					d.Set("failed_task_logs", failedTasksLog)

					if !isSuccess && failureReason == "No specific failure reason found in logs" {
						// Try to find failure info directly in the workflow response
						if message, ok := firstRequest["message"].(string); ok && message != "" {
							logger.Debug(" Found message in workflow: %s", message)
							if containsAny(message, []string{"Failed", "Error", "failed", "error"}) {
								failureReason = message
							}
						}

						// If still no reason, check if there's a tooltip
						if tooltip, ok := firstRequest["toolTip"].(string); ok && tooltip != "" {
							logger.Debug(" Found tooltip in workflow: %s", tooltip)
							failureReason = tooltip
						}
					}
				} else {
					logger.Warn(" No tasks found in revoke workflow response")
				}

				// Generate pretty response message
				responseMessage = buildResponseMessage(firstRequest, statusCode, failureReason)
			}
		}
	}

	// Add the failure reason to the response message if it exists
	if failureReason != "" && failureReason != "No specific failure reason found in logs" {
		logger.Info(" Revoke failure reason: %s", failureReason)
	}

	// Set the response message and failure reason
	d.Set("response_message", responseMessage)
	d.Set("failure_reason", failureReason)
}
