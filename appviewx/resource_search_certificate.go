package appviewx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"terraform-provider-appviewx/appviewx/config"
	"terraform-provider-appviewx/appviewx/constants"
	"terraform-provider-appviewx/appviewx/logger"
)

func ResourceSearchCertificateByKeyword() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceSearchCertificateByKeywordCreate,
		ReadContext:   resourceSearchCertificateByKeywordRead,
		UpdateContext: resourceSearchCertificateByKeywordUpdate,
		DeleteContext: resourceSearchCertificateByKeywordDelete,

		Schema: map[string]*schema.Schema{
			"category": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Category of certificate (e.g., Server)",
			},
			"cert_serial_no": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Certificate serial number",
			},
			"cert_issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Certificate issuer",
			},
			"cert_cn": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Certificate common name",
			},
			"cert_san": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Certificate SAN",
			},
			"max_results": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     10,
				Description: "Maximum number of results to return",
			},
			"start_index": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     1,
				Description: "Start index for pagination",
			},
			"sort_column": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "commonName",
				Description: "Column to sort results by",
			},
			"sort_order": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "desc",
				Description: "Sort order (asc or desc)",
			},
			"total_records": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Total number of records found",
			},
			"certificate_uuid": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate UUID from search results",
			},
			"certificate_common_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate common name (CN) from search results",
			},
			"certificate_serial_number": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate serial number from search results",
			},
			"certificate_issuer": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate issuer from search results",
			},
			"certificate_status": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate status from search results",
			},
			"certificate_valid_from": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate valid from date",
			},
			"certificate_valid_to": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate valid to date (expiration)",
			},
			"certificate_valid_for": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate validity period in days",
			},
			"certificate_key_algorithm": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate key algorithm",
			},
			"certificate_signature_algorithm": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate signature algorithm",
			},
			"certificate_thumbprint": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate thumbprint/fingerprint",
			},
			"certificate_resource_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate resource ID in AppViewX",
			},
			"certificate_subject_alternative_names": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate Subject Alternative Names (SANs) as JSON string",
			},
			"certificate_version": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate version",
			},
			"certificate_organization": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate organization (O)",
			},
			"certificate_organizational_unit": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate organizational unit (OU)",
			},
			"certificate_country": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate country (C)",
			},
			"certificate_province": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate state/province (ST)",
			},
			"certificate_locality": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate locality/city (L)",
			},
			"certificate_email": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate email address",
			},
			"certificate_expiry_status": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate expiry status (e.g., Active, Revoked, Expired)",
			},
			// Azure Key Vault Information
			"key_vault_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the Azure Key Vault",
			},
			"key_vault_secret_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the secret in Azure Key Vault",
			},
			// Enhanced Certificate Metadata
			"validity_period": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate validity period duration",
			},
			"certificate_authority": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate Authority that issued the certificate",
			},
			// Epoch timestamps (Unix time in milliseconds)
			"certificate_valid_from_epoch": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Unix timestamp when the certificate was issued (milliseconds)",
			},
			"certificate_valid_to_epoch": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Unix timestamp when the certificate expires (milliseconds)",
			},
			// Additional metadata from response
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
			"subject_key_identifier": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate subject key identifier",
			},
			"authority_key_identifier": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate authority key identifier",
			},
			"compliance_status": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Certificate compliance status",
			},
		},
	}
}

func resourceSearchCertificateByKeywordCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	logger.Info("\n====================[CERTIFICATE SEARCH]====================")
	logger.Info("  🚀  Resource Search Certificate By Keyword Create")
	logger.Info("==================================================================\n")

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
			logger.Error("❌ Error in getting the session:")
			logger.Error("   ", err)
			logger.Error("----------------------------------------------------------------------")
			return diag.FromErr(err)
		}
	} else if appviewxClientId != "" && appviewxClientSecret != "" {
		accessToken, err = GetAccessToken(appviewxClientId, appviewxClientSecret, appviewxEnvironmentIP, appviewxEnvironmentPort, appviewxGwSource, appviewxEnvironmentIsHTTPS)
		if err != nil {
			logger.Error("❌ Error in getting the access token:")
			logger.Error("   ", err)
			logger.Error("----------------------------------------------------------------------")
			return diag.FromErr(err)
		}
	}

	result, err := searchCertificatesByKeyword(d, configAppViewXEnvironment, appviewxSessionID, accessToken)
	if err != nil {
		return diag.FromErr(err)
	}

	// Set resource ID to something unique to identify this search
	searchId := fmt.Sprintf("cert_search_%s", d.Get("category").(string))
	d.SetId(searchId)

	// Only store non-sensitive metadata in state
	d.Set("total_records", result.TotalRecords)

	// Populate certificate metadata from the first certificate found (if any)
	if len(result.Certificates) > 0 {
		firstCert := result.Certificates[0]
		logger.Info("📋 Populating certificate metadata from first search result: %s", firstCert.CommonName)

		// Set all the certificate metadata fields
		d.Set("certificate_uuid", firstCert.UUID)
		d.Set("certificate_common_name", firstCert.CommonName)
		d.Set("certificate_serial_number", firstCert.SerialNumber)
		d.Set("certificate_issuer", firstCert.Issuer)
		d.Set("certificate_status", firstCert.Status)
		d.Set("certificate_valid_from", firstCert.ValidFrom)
		d.Set("certificate_valid_to", firstCert.ValidTo)
		d.Set("certificate_valid_for", firstCert.ValidFor)

		// Set epoch timestamps if available
		if firstCert.ValidFromEpoch > 0 {
			d.Set("certificate_valid_from_epoch", firstCert.ValidFromEpoch)
		}
		if firstCert.ValidToEpoch > 0 {
			d.Set("certificate_valid_to_epoch", firstCert.ValidToEpoch)
		}

		d.Set("certificate_key_algorithm", firstCert.KeyAlgorithm)
		d.Set("certificate_signature_algorithm", firstCert.SignatureAlgorithm)
		d.Set("certificate_thumbprint", firstCert.ThumbPrint)
		d.Set("certificate_resource_id", firstCert.ResourceID)

		// Set additional metadata if available in the Certificate struct
		if firstCert.Version != "" {
			d.Set("certificate_version", firstCert.Version)
		}
		if firstCert.Organization != "" {
			d.Set("certificate_organization", firstCert.Organization)
		}
		if firstCert.OrganizationalUnit != "" {
			d.Set("certificate_organizational_unit", firstCert.OrganizationalUnit)
		}
		if firstCert.Country != "" {
			d.Set("certificate_country", firstCert.Country)
		}
		if firstCert.State != "" {
			d.Set("certificate_province", firstCert.State)
		}
		if firstCert.Locality != "" {
			d.Set("certificate_locality", firstCert.Locality)
		}
		if firstCert.Email != "" {
			d.Set("certificate_email", firstCert.Email)
		}
		if firstCert.SubjectAlternativeNames != "" {
			d.Set("certificate_subject_alternative_names", firstCert.SubjectAlternativeNames)
		}
		if firstCert.ExpiryStatus != "" {
			d.Set("certificate_expiry_status", firstCert.ExpiryStatus)
		}

		// Azure Key Vault Information
		if firstCert.KeyVaultName != "" {
			d.Set("key_vault_name", firstCert.KeyVaultName)
		}
		if firstCert.KeyVaultSecretName != "" {
			d.Set("key_vault_secret_name", firstCert.KeyVaultSecretName)
		}

		// Enhanced Certificate Metadata
		if firstCert.ValidityPeriod != "" {
			d.Set("validity_period", firstCert.ValidityPeriod)
		}
		if firstCert.CertificateAuthority != "" {
			d.Set("certificate_authority", firstCert.CertificateAuthority)
		}

		// Additional security fields
		if firstCert.KeyUsage != "" {
			d.Set("key_usage", firstCert.KeyUsage)
		}
		if firstCert.ExtendedKeyUsage != "" {
			d.Set("extended_key_usage", firstCert.ExtendedKeyUsage)
		}
		if firstCert.SubjectKeyIdentifier != "" {
			d.Set("subject_key_identifier", firstCert.SubjectKeyIdentifier)
		}
		if firstCert.AuthorityKeyIdentifier != "" {
			d.Set("authority_key_identifier", firstCert.AuthorityKeyIdentifier)
		}
		if firstCert.ComplianceStatus != "" {
			d.Set("compliance_status", firstCert.ComplianceStatus)
		}

		logger.Info("✅ Certificate metadata populated for: %s (Serial: %s)", firstCert.CommonName, firstCert.SerialNumber)
	} else {
		logger.Info("ℹ️  No certificates found in search results - metadata fields will remain empty")
	}

	// DO NOT store certificates or raw response in state

	logger.Info("✅ Search complete with %d total records\n", result.TotalRecords)

	// Check for final search validation errors after processing
	if result.RawResponse == "" {
		return diag.FromErr(fmt.Errorf("certificate search failed - no response received from server"))
	}

	// Check if search returned error information in the response structure
	var responseObj map[string]interface{}
	if err := json.Unmarshal([]byte(result.RawResponse), &responseObj); err == nil {
		if topResponse, ok := responseObj["response"].(map[string]interface{}); ok {
			if errorMsg, ok := topResponse["errorMessage"].(string); ok && errorMsg != "" {
				return diag.FromErr(fmt.Errorf("certificate search failed: %s", errorMsg))
			}
			if status, ok := topResponse["status"].(string); ok && status != "success" {
				if message, ok := topResponse["message"].(string); ok && message != "" {
					return diag.FromErr(fmt.Errorf("certificate search failed with status '%s': %s", status, message))
				} else {
					return diag.FromErr(fmt.Errorf("certificate search failed with status: %s", status))
				}
			}
		}
	}
	return nil
}

// Structure for search results
type CertificateSearchResult struct {
	RawResponse  string
	TotalRecords int
	Certificates []Certificate
}

// Structure for certificate details
type Certificate struct {
	ID           string
	UUID         string
	CommonName   string
	SerialNumber string
	Issuer       string
	Status       string
	ValidFrom    string
	ValidTo      string
	ValidFor     string
	// Epoch timestamps
	ValidFromEpoch          int64
	ValidToEpoch            int64
	KeyAlgorithm            string
	SignatureAlgorithm      string
	ThumbPrint              string
	ResourceID              string
	KeySize                 int
	Version                 string
	Organization            string
	OrganizationalUnit      string
	Country                 string
	State                   string
	Locality                string
	Email                   string
	SubjectAlternativeNames string
	ExpiryStatus            string
	// Azure Key Vault fields
	KeyVaultName       string
	KeyVaultSecretName string
	// Enhanced metadata
	ValidityPeriod         string
	CertificateAuthority   string
	KeyUsage               string
	ExtendedKeyUsage       string
	SubjectKeyIdentifier   string
	AuthorityKeyIdentifier string
	ComplianceStatus       string
}

func searchCertificatesByKeyword(d *schema.ResourceData, configAppViewXEnvironment *config.AppViewXEnvironment, appviewxSessionID, accessToken string) (CertificateSearchResult, error) {
	var result CertificateSearchResult
	httpMethod := config.HTTPMethodPost
	appviewxEnvironmentIP := configAppViewXEnvironment.AppViewXEnvironmentIP
	appviewxEnvironmentPort := configAppViewXEnvironment.AppViewXEnvironmentPort
	appviewxEnvironmentIsHTTPS := configAppViewXEnvironment.AppViewXIsHTTPS

	// Set query parameters exactly as in curl
	queryParams := map[string]string{
		"gwkey":    "f000ca01",
		"gwsource": "external",
	}

	// Get URL
	url := GetURL(appviewxEnvironmentIP, appviewxEnvironmentPort, "certificate/search", queryParams, appviewxEnvironmentIsHTTPS)

	logger.Debug("🔍 Searching certificates using URL: %s", url)

	// Build search payload
	payload := buildSearchPayload(d)

	// Pretty print payload
	payloadBytes, _ := json.MarshalIndent(payload, "", "  ")
	logger.Debug("📝 Search payload:\n%s\n", string(payloadBytes))

	requestBody, err := json.Marshal(payload)
	if err != nil {
		logger.Error("❌ Error in Marshalling the payload:")
		logger.Error("   ", err)
		logger.Debug("   Payload: %+v\n", payload)
		logger.Debug("------------------------------------------------------------------\n")
		return result, err
	}

	client := &http.Client{Transport: HTTPTransport()}

	logger.Debug("🌐 Making request to %s\n", url)

	req, err := http.NewRequest(httpMethod, url, bytes.NewBuffer(requestBody))
	if err != nil {
		logger.Error("❌ Error in creating new Request:")
		logger.Error("   ", err)
		logger.Debug("------------------------------------------------------------------\n")
		return result, err
	}

	// Set headers directly instead of using frameHeaders()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Add session ID header
	if appviewxSessionID != "" {
		logger.Debug("🔑 Using session ID for authentication")
		req.Header.Set(constants.SESSION_ID, appviewxSessionID)
	} else if accessToken != "" {
		logger.Debug("🔑 Using access token for authentication")
		req.Header.Set(constants.TOKEN, accessToken)
	}

	// Debug headers with pretty print
	// headersBytes, _ := json.MarshalIndent(req.Header, "", "  ")
	// log.Printf("[CERTIFICATE SEARCH][DEBUG] 🏷️ Request headers:\n%s\n", string(headersBytes))

	httpResponse, err := client.Do(req)
	if err != nil {
		logger.Error("❌ Error in searching certificates:")
		logger.Error("   ", err)
		logger.Error("----------------------------------------------------------------------")
		return result, err
	}
	defer httpResponse.Body.Close()

	logger.Info("📊 Search certificates response status code: %s\n", httpResponse.Status)

	// Read response body
	responseBody, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		logger.Error("Unable to read response body: ", err)
		return result, err
	}

	// Log full response for debugging
	// Format and log JSON response for better readability
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, responseBody, "", "  "); err != nil {
		logger.Info("📦 Search response body (raw):\n%s\n", string(responseBody))
	} else {
		logger.Info("📦 Search response body :\n%s\n", prettyJSON.String())
	}

	// Store raw response
	result.RawResponse = string(responseBody)

	// Check for error responses
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		logger.Error("❌ Error response received:")
		logger.Error("   Status code:", httpResponse.Status)
		logger.Error("   Response: %s\n", string(responseBody))
		logger.Error("----------------------------------------------------------------------")
		return result, errors.New("error in searching certificates: " + string(responseBody))
	}

	// Parse response
	var responseObj map[string]interface{}
	if err := json.Unmarshal(responseBody, &responseObj); err != nil {
		logger.Error("[ERROR] Unable to unmarshal the response: ", err)
		return result, err
	}

	// Extract total records and certificates from the proper path in the response structure
	if topResponse, ok := responseObj["response"].(map[string]interface{}); ok {
		if innerResponse, ok := topResponse["response"].(map[string]interface{}); ok {
			// Extract totalRecords
			if totalRecords, ok := innerResponse["totalRecords"].(float64); ok {
				result.TotalRecords = int(totalRecords)
			}

			// Extract certificate records from "objects" array
			if objects, ok := innerResponse["objects"].([]interface{}); ok {
				for _, record := range objects {
					if certMap, ok := record.(map[string]interface{}); ok {
						cert := Certificate{}

						// Basic certificate fields
						if val, ok := certMap["resourceId"].(string); ok {
							cert.ResourceID = val
						}
						if val, ok := certMap["uuid"].(string); ok {
							cert.UUID = val
							cert.ID = val // Use UUID as ID if no specific ID field
						}
						if val, ok := certMap["commonName"].(string); ok {
							cert.CommonName = val
						}
						if val, ok := certMap["serialNumber"].(string); ok {
							cert.SerialNumber = val
						}
						if val, ok := certMap["issuerCommonName"].(string); ok {
							cert.Issuer = val
						} else if val, ok := certMap["issuer"].(string); ok {
							cert.Issuer = val
						}
						if val, ok := certMap["status"].(string); ok {
							cert.Status = val
						}

						// Date fields - convert milliseconds to readable date format and store epoch
						if val, ok := certMap["validFrom"].(float64); ok {
							// Convert milliseconds to time
							t := time.Unix(int64(val/1000), 0)
							cert.ValidFrom = t.Format("2006-01-02 15:04:05")
							cert.ValidFromEpoch = int64(val)
						} else if val, ok := certMap["validFrom"].(string); ok {
							cert.ValidFrom = val
						}
						if val, ok := certMap["validTo"].(float64); ok {
							// Convert milliseconds to time
							t := time.Unix(int64(val/1000), 0)
							cert.ValidTo = t.Format("2006-01-02 15:04:05")
							cert.ValidToEpoch = int64(val)
						} else if val, ok := certMap["validTo"].(string); ok {
							cert.ValidTo = val
						}
						if val, ok := certMap["validFor"].(string); ok {
							cert.ValidFor = val
						}

						// Algorithm and security fields
						if val, ok := certMap["keyAlgorithmAndSize"].(string); ok {
							cert.KeyAlgorithm = val
						} else if val, ok := certMap["keyAlgorithm"].(string); ok {
							cert.KeyAlgorithm = val
						}
						if val, ok := certMap["signatureAlgorithm"].(string); ok {
							cert.SignatureAlgorithm = val
						}
						if val, ok := certMap["thumbPrint"].(string); ok {
							cert.ThumbPrint = val
						} else if val, ok := certMap["fingerprint"].(string); ok {
							cert.ThumbPrint = val
						}

						// Additional metadata fields
						if val, ok := certMap["keySize"].(float64); ok {
							cert.KeySize = int(val)
						} else if val, ok := certMap["keySize"].(int); ok {
							cert.KeySize = val
						}
						if val, ok := certMap["version"].(string); ok {
							cert.Version = val
						} else if val, ok := certMap["version"].(float64); ok {
							cert.Version = fmt.Sprintf("%.0f", val)
						}
						// Subject fields - use the correct field names from API response
						if val, ok := certMap["subjectOrganization"].(string); ok {
							cert.Organization = val
						} else if val, ok := certMap["organization"].(string); ok {
							cert.Organization = val
						} else if val, ok := certMap["o"].(string); ok {
							cert.Organization = val
						}
						if val, ok := certMap["subjectOrganizationUnit"].(string); ok {
							cert.OrganizationalUnit = val
						} else if val, ok := certMap["organizationalUnit"].(string); ok {
							cert.OrganizationalUnit = val
						} else if val, ok := certMap["ou"].(string); ok {
							cert.OrganizationalUnit = val
						}
						if val, ok := certMap["subjectCountry"].(string); ok {
							cert.Country = val
						} else if val, ok := certMap["country"].(string); ok {
							cert.Country = val
						} else if val, ok := certMap["c"].(string); ok {
							cert.Country = val
						}
						if val, ok := certMap["subjectState"].(string); ok {
							cert.State = val
						} else if val, ok := certMap["state"].(string); ok {
							cert.State = val
						} else if val, ok := certMap["st"].(string); ok {
							cert.State = val
						}
						if val, ok := certMap["subjectLocality"].(string); ok {
							cert.Locality = val
						} else if val, ok := certMap["locality"].(string); ok {
							cert.Locality = val
						} else if val, ok := certMap["l"].(string); ok {
							cert.Locality = val
						}
						// Extract email from subject string since it's not a separate field
						if subject, ok := certMap["subject"].(string); ok {
							// Parse subject string to extract email
							if emailStart := strings.Index(subject, "EMAILADDRESS="); emailStart != -1 {
								emailStart += len("EMAILADDRESS=")
								emailEnd := emailStart
								for i := emailStart; i < len(subject); i++ {
									if subject[i] == ',' || subject[i] == ' ' {
										break
									}
									emailEnd = i + 1
								}
								cert.Email = subject[emailStart:emailEnd]
							}
						}

						// Subject Alternative Names - handle array format
						if sans, ok := certMap["subjectAlternativeNames"].([]interface{}); ok {
							var sanList []string
							for _, san := range sans {
								if sanStr, ok := san.(string); ok {
									sanList = append(sanList, sanStr)
								}
							}
							if len(sanList) > 0 {
								cert.SubjectAlternativeNames = strings.Join(sanList, ", ")
							}
						} else if val, ok := certMap["subjectAlternativeNames"].(string); ok {
							cert.SubjectAlternativeNames = val
						} else if val, ok := certMap["sans"].(string); ok {
							cert.SubjectAlternativeNames = val
						} else if val, ok := certMap["san"].(string); ok {
							cert.SubjectAlternativeNames = val
						}

						// Expiry Status
						if val, ok := certMap["expiryStatus"].(string); ok {
							cert.ExpiryStatus = val
						}

						// Azure Key Vault Information
						if deviceDetails, ok := certMap["deviceDetails"].(map[string]interface{}); ok {
							if val, ok := deviceDetails["deviceName"].(string); ok {
								cert.KeyVaultName = val
							}
							if attributes, ok := deviceDetails["attributes"].(map[string]interface{}); ok {
								if val, ok := attributes["certificateFileName"].(string); ok {
									cert.KeyVaultSecretName = val
								}
								if val, ok := attributes["keyVaultName"].(string); ok && cert.KeyVaultName == "" {
									cert.KeyVaultName = val
								}
							}
						}

						// Enhanced Certificate Metadata
						if val, ok := certMap["validFor"].(string); ok {
							cert.ValidityPeriod = val
						}
						if val, ok := certMap["certificateAuthority"].(string); ok {
							cert.CertificateAuthority = val
						}

						// Additional security fields
						if val, ok := certMap["keyUsage"].(string); ok {
							cert.KeyUsage = val
						}
						if val, ok := certMap["extendedKeyUsage"].(string); ok {
							cert.ExtendedKeyUsage = val
						}
						if val, ok := certMap["subjectKeyIdentifier"].(string); ok {
							cert.SubjectKeyIdentifier = val
						}
						if val, ok := certMap["authorityKeyIdentifier"].(string); ok {
							cert.AuthorityKeyIdentifier = val
						}
						if val, ok := certMap["complianceStatus"].(string); ok {
							cert.ComplianceStatus = val
						}

						logger.Debug("📋 Parsed certificate: CN=%s, Serial=%s, ResourceID=%s, ExpiryStatus=%s", cert.CommonName, cert.SerialNumber, cert.ResourceID, cert.ExpiryStatus)
						result.Certificates = append(result.Certificates, cert)
					}
				}
			}
		}
	}

	logger.Info("✅ Extracted %d certificates from response\n", len(result.Certificates))
	logger.Info("==================================================================\n")
	return result, nil
}

func buildSearchPayload(d *schema.ResourceData) map[string]interface{} {
	category := d.Get("category").(string)
	maxResults := d.Get("max_results").(int)
	startIndex := d.Get("start_index").(int)
	sortColumn := d.Get("sort_column").(string)
	sortOrder := d.Get("sort_order").(string)

	// Build keyword search payload
	keywordSearch := make(map[string]interface{})

	// Add search criteria if provided
	if serialNo, ok := d.GetOk("cert_serial_no"); ok {
		keywordSearch["certserialno"] = serialNo.(string)
	}
	if issuer, ok := d.GetOk("cert_issuer"); ok {
		keywordSearch["certissuer"] = issuer.(string)
	}
	if cn, ok := d.GetOk("cert_cn"); ok {
		keywordSearch["certcn"] = cn.(string)
	}
	if san, ok := d.GetOk("cert_san"); ok {
		keywordSearch["certsan"] = san.(string)
	}

	// Build filter payload
	filter := map[string]interface{}{
		"max":        fmt.Sprintf("%d", maxResults),
		"start":      fmt.Sprintf("%d", startIndex),
		"sortColumn": sortColumn,
		"sortOrder":  sortOrder,
	}

	// Build the complete payload
	payload := map[string]interface{}{
		"input": map[string]interface{}{
			"category":      category,
			"keywordSearch": keywordSearch,
		},
		"filter": filter,
	}

	// Log the final search criteria
	logger.Debug("🔍 Search criteria: Category=%s, Results=%d-%d, Sort=%s %s\n",
		category, startIndex, startIndex+maxResults-1, sortColumn, sortOrder)

	return payload
}

func resourceSearchCertificateByKeywordRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	logger.Info("ℹ️ GET OPERATION RETURNS EXISTING DATA\n")

	// Preserve all certificate metadata fields to avoid drift warnings
	certificateFields := []string{
		"total_records", "certificate_uuid", "certificate_common_name",
		"certificate_serial_number", "certificate_issuer", "certificate_status",
		"certificate_valid_from", "certificate_valid_to", "certificate_valid_for",
		"certificate_key_algorithm", "certificate_signature_algorithm", "certificate_thumbprint",
		"certificate_resource_id", "certificate_subject_alternative_names",
		"certificate_version", "certificate_organization", "certificate_organizational_unit",
		"certificate_country", "certificate_province", "certificate_locality", "certificate_email",
		"certificate_expiry_status",
		// Azure Key Vault fields
		"key_vault_name", "key_vault_secret_name",
		// Enhanced metadata fields
		"validity_period", "certificate_authority",
		"certificate_valid_from_epoch", "certificate_valid_to_epoch",
		"key_usage", "extended_key_usage", "subject_key_identifier",
		"authority_key_identifier", "compliance_status",
	}

	for _, field := range certificateFields {
		if v, ok := d.GetOk(field); ok {
			d.Set(field, v)
		}
	}

	return nil
}

func resourceSearchCertificateByKeywordUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	logger.Info("🔄 UPDATE OPERATION TRIGGERS NEW SEARCH\n")
	return resourceSearchCertificateByKeywordCreate(ctx, d, m)
}

func resourceSearchCertificateByKeywordDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	logger.Info("🗑️ Removing certificate search resource from state\n")
	d.SetId("")
	return nil
}
