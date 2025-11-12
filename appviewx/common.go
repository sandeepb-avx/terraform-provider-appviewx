package appviewx

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"terraform-provider-appviewx/appviewx/config"
	"terraform-provider-appviewx/appviewx/constants"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func printRequest(types, url string, headers map[string]interface{}, requestBody []byte) {
	log.Println("[INFO] ***************** Making a API Request to AppViewX **********************")
	log.Println("[INFO] HTTP Method : ", types)
	log.Println("[INFO] URL : ", url)
	//log.Println("[DEBUG] Headers : ", headers)
	//log.Println("[DEBUG] Request Payload : ", string(requestBody))
	log.Println("[INFO] *********************************************************")
}

// TODO: cleanup to be done
func GetSession(
	appviewxUserName,
	appviewxPassword,
	appviewxEnvironmentIP,
	appviewxEnvironmentPort,
	appviewxGwSource string,
	appviewxEnvironmentIsHTTPS bool,
) (output string, err error) {

	log.Println("[INFO] Request received for fetching session id")

	payload := make(map[string]interface{})

	headers := make(map[string]interface{})
	headers[constants.CONTENT_TYPE] = constants.APPLICATION_JSON
	headers[constants.ACCEPT] = constants.APPLICATION_JSON
	headers[constants.USERNAME] = appviewxUserName
	headers[constants.PASSWORD] = appviewxPassword

	actionID := constants.APPVIEWX_ACTION_ID_LOGIN

	queryParams := make(map[string]string)
	queryParams[constants.GW_SOURCE] = appviewxGwSource

	url := GetURL(appviewxEnvironmentIP, appviewxEnvironmentPort, actionID, queryParams, appviewxEnvironmentIsHTTPS)

	payloadContents, err := json.Marshal(payload)
	if err != nil {
		log.Println("[ERROR] Error in marshalling the payload", payload, err)
		return "", err
	}

	payloadContentsReader := bytes.NewReader(payloadContents)

	printRequest(constants.POST, url, headers, payloadContents)

	client := &http.Client{Transport: HTTPTransport()}
	req, err := http.NewRequest(constants.POST, url, payloadContentsReader)
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
			return "", errors.New("error in getting the session id due to " + string(responseBody))
		}
	}
	defer resp.Body.Close()
	responseContents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("[ERROR] error in reading the response body", err)
		return "", err
	}

	map1 := make(map[string]interface{})
	err = json.Unmarshal(responseContents, &map1)
	if err != nil {
		log.Println("[ERROR] Error in Unmarshalling the responseContents", err)
		return "", err
	}

	if map1[constants.RESPONSE] != nil {
		responseMap := map1[constants.RESPONSE].(map[string]interface{})
		if responseMap != nil && responseMap[constants.SESSION_ID] != nil {
			log.Println("[INFO] Session id retrieval success, sessionid will be used for AppViewX API calls")
			return responseMap[constants.SESSION_ID].(string), nil
		}
	}
	log.Println("[ERROR] Session id retrieval failed ")
	return "", nil
}

func HTTPTransport() *http.Transport {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return tr
}

func GetDownloadFormat(resourceData *schema.ResourceData) string {
	if resourceData.Get(constants.CERTIFICATE_DOWNLOAD_FORMAT) != nil {
		return resourceData.Get(constants.CERTIFICATE_DOWNLOAD_FORMAT).(string)
	} else {
		return "CRT"
	}
}

func GetDownloadFilePath(resourceData *schema.ResourceData, commonName, downloadFormat string) string {
	workingDir, _ := os.Getwd()
	if resourceData.Get(constants.CERTIFICATE_DOWNLOAD_PATH) == nil && resourceData.Get(constants.COMMON_NAME) != nil {
		log.Println("[INFO] " + "Download path not provided hence saving file in current working directory with common name")
		return workingDir + commonName + "." + strings.ToLower(downloadFormat)
	} else {
		downloadPath := resourceData.Get(constants.CERTIFICATE_DOWNLOAD_PATH).(string)
		log.Println("[INFO] Download path provided = ", downloadPath)
		fileInfo, err := os.Stat(downloadPath)
		if err == nil {
			if fileInfo.IsDir() {
				log.Println("[INFO] " + downloadPath + " is a directory hence saving file with common name")
				return downloadPath + commonName + "." + strings.ToLower(downloadFormat)
			} else {
				log.Println("[INFO] " + downloadPath + " is a file hence saving file with provided file name")
				return downloadPath + "." + strings.ToLower(downloadFormat)
			}
		} else if os.IsNotExist(err) {
			parentDir := filepath.Dir(downloadPath)
			fileInfo, _ := os.Stat(parentDir)
			if !fileInfo.IsDir() {
				log.Println("[INFO] Directory : " + parentDir + " does not exist, creating directory and saving file with common name")
				err := os.MkdirAll(parentDir, 0755)
				if err != nil {
					log.Println("[INFO] Error creating directory: "+parentDir+" due to : ", err)
					return downloadPath + "." + strings.ToLower(downloadFormat)
				}
				log.Println("[INFO] Created a directory " + parentDir + " and saving file with provided file name")
			} else {
				log.Println("[INFO] Directory : " + parentDir + " already exists, saving file with provided file name")
			}
		}
		return downloadPath + "." + strings.ToLower(downloadFormat)
	}
}

func GetDownloadFilePathForKey(resourceData *schema.ResourceData, commonName, downloadFormat string) string {
	workingDir, _ := os.Getwd()
	if resourceData.Get(constants.KEY_DOWNLOAD_PATH) == nil && resourceData.Get(constants.COMMON_NAME) != nil {
		log.Println("[INFO] " + "Download path not provided hence saving file in current working directory with common name")
		return workingDir + commonName + "." + strings.ToLower(downloadFormat)
	} else {
		downloadPath := resourceData.Get(constants.KEY_DOWNLOAD_PATH).(string)
		log.Println("[INFO] Download path provided = ", downloadPath)
		fileInfo, err := os.Stat(downloadPath)
		if err == nil {
			if fileInfo.IsDir() {
				log.Println("[INFO] " + downloadPath + " is a directory hence saving file with common name")
				return downloadPath + commonName + "." + strings.ToLower(downloadFormat)
			} else {
				log.Println("[INFO] " + downloadPath + " is a file hence saving file with provided file name")
				return downloadPath + "." + strings.ToLower(downloadFormat)
			}
		} else if os.IsNotExist(err) {
			parentDir := filepath.Dir(downloadPath)
			fileInfo, _ := os.Stat(parentDir)
			if !fileInfo.IsDir() {
				log.Println("[INFO] Directory : " + parentDir + " does not exist, creating directory and saving file with common name")
				err := os.MkdirAll(parentDir, 0755)
				if err != nil {
					log.Println("[INFO] Error creating directory: "+parentDir+" due to : ", err)
					return downloadPath + "." + strings.ToLower(downloadFormat)
				}
				log.Println("[INFO] Created a directory " + parentDir + " and saving file with provided file name")
			} else {
				log.Println("[INFO] Directory : " + parentDir + " already exists, saving file with provided file name")
			}
		}
		return downloadPath + "." + strings.ToLower(downloadFormat)
	}
}

func GetDownloadPassword(resourceData *schema.ResourceData, downloadFormat string, configAppviewxEnvironment *config.AppViewXEnvironment) (string, bool) {
	password := getPasswordWithPriority(configAppviewxEnvironment.ProviderCertDownloadPassword, resourceData.Get(constants.CERTIFICATE_DOWNLOAD_PASSWORD).(string))
	if password != "" && (downloadFormat == "PFX" || downloadFormat == "JKS" || downloadFormat == "P12") {
		return password, true
	} else if password == "" && (downloadFormat == "PFX" || downloadFormat == "JKS" || downloadFormat == "P12") {
		log.Println("[ERROR] Password not found for the specified download format - " + downloadFormat)
		return "", false
	}
	return "", true
}

func downloadCertificateFromAppviewx(appviewxResourceId, commonName, serialNumber, downloadFormat, downloadPassword, downloadPath string, isChainRequired bool, appviewxSessionID, appviewxAccessToken string, configAppViewXEnvironment *config.AppViewXEnvironment) bool {
	httpMethod := config.HTTPMethodPost
	appviewxEnvironmentIP := configAppViewXEnvironment.AppViewXEnvironmentIP
	appviewxEnvironmentPort := configAppViewXEnvironment.AppViewXEnvironmentPort
	appviewxEnvironmentIsHTTPS := configAppViewXEnvironment.AppViewXIsHTTPS
	headers := frameHeaders()
	url := GetURL(appviewxEnvironmentIP, appviewxEnvironmentPort, config.DownloadCertificateActionId, frameQueryParams(), appviewxEnvironmentIsHTTPS)
	payload := frameDownloadCertificatePayload(appviewxResourceId, commonName, serialNumber, downloadFormat, downloadPassword, isChainRequired)
	requestBody, err := json.Marshal(payload)
	if err != nil {
		log.Println("[ERROR] error in Marshalling the payload ", payload, err)
		return false
	}
	client := &http.Client{Transport: HTTPTransport()}

	printRequest(httpMethod, url, headers, requestBody)

	req, err := http.NewRequest(httpMethod, url, bytes.NewBuffer(requestBody))
	if err != nil {
		log.Println("[ERROR] error in creating new Request", err)
		return false
	}

	for key, value := range headers {
		value1 := fmt.Sprintf("%v", value)
		key1 := fmt.Sprintf("%v", key)
		req.Header.Add(key1, value1)
	}
	if appviewxSessionID != "" {
		req.Header.Add(constants.SESSION_ID, appviewxSessionID)
	} else {
		req.Header.Add(constants.TOKEN, appviewxAccessToken)
	}
	httpResponse, err := client.Do(req)
	if err != nil {
		log.Println("[ERROR] error in http request", err)
		return false
	} else {
		log.Println("[INFO] Request for downloading the certificate submitted successfully")
	}
	log.Println("[INFO] Response status code : ", httpResponse.Status)
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		responseBody, err := io.ReadAll(httpResponse.Body)
		if err == nil {
			log.Println("[ERROR] Response obtained : ", string(responseBody))
			return false
		}
	}
	responseByte, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		log.Println("[ERROR] ", err)
		return false
	} else {
		err = os.WriteFile(downloadPath, responseByte, 0777)
		if err != nil {
			log.Println("[ERROR] Error while downloading the certificate file content in ", downloadPath, " due to : ", err)
			return false
		} else {
			log.Println("[INFO] Downloaded certificate file and available in ", downloadPath)
			return true
		}
	}

}

func downloadKey(resourceData *schema.ResourceData, resourceID, appviewxSessionID, accessToken string, configAppViewXEnvironment *config.AppViewXEnvironment) error {
	commonName := resourceData.Get(constants.COMMON_NAME).(string)
	downloadPath := GetDownloadFilePathForKey(resourceData, commonName+"_key", "PEM")
	providerKeyPassword := configAppViewXEnvironment.ProviderKeyDownloadPassword
	resourceKeyPassword := resourceData.Get(constants.KEY_DOWNLOAD_PASSWORD).(string)
	downloadPassword := getPasswordWithPriority(providerKeyPassword, resourceKeyPassword)
	downloadPasswordProtectedKey := resourceData.Get(constants.DOWNLOAD_PASSWORD_PROTECTED_KEY).(bool)

	if downloadPassword == "" {
		log.Println("[ERROR] Password not found for private key download")
		return errors.New("[ERROR] Password not found for private key download")
	}

	searchResponse := searchCertificate(resourceID, appviewxSessionID, accessToken, configAppViewXEnvironment)
	if searchResponse.AppviewxResponse.ResponseObject.Objects != nil && searchResponse.AppviewxResponse.ResponseObject.Objects[0].UUID == "" {
		log.Println("[ERROR] Cannot find the UUID for the resource id " + resourceID + " to proceed with key download")
		return errors.New("[ERROR] Certificate details was not found to download the private key")
	}
	uuid := searchResponse.AppviewxResponse.ResponseObject.Objects[0].UUID
	log.Println("[INFO] UUID for the resource id " + resourceID + " was obtained successfully")
	if downloadSuccess := downloadKeyFromAppviewx(uuid, downloadPassword, downloadPath, downloadPasswordProtectedKey, appviewxSessionID, accessToken, configAppViewXEnvironment); downloadSuccess {
		log.Println("[INFO] Private key downloaded successfully in the specified path")
		resourceData.SetId(strconv.Itoa(rand.Int()))
	} else {
		log.Println("[ERROR] Private key was not downloaded in the specified path")
		return errors.New("[ERROR] Private key was not downloaded in the specified path")
	}
	return nil
}

func downloadKeyFromAppviewx(uuid, downloadPassword, downloadPath string, downloadPasswordProtectedKey bool, appviewxSessionID, appviewxAccessToken string, configAppViewXEnvironment *config.AppViewXEnvironment) bool {
	httpMethod := config.HTTPMethodPost
	var response config.AppviewxDownloadKeyResponse
	var responseByte []byte
	appviewxEnvironmentIP := configAppViewXEnvironment.AppViewXEnvironmentIP
	appviewxEnvironmentPort := configAppViewXEnvironment.AppViewXEnvironmentPort
	appviewxEnvironmentIsHTTPS := configAppViewXEnvironment.AppViewXIsHTTPS
	headers := frameHeaders()
	url := GetURL(appviewxEnvironmentIP, appviewxEnvironmentPort, config.DownloadKeyActionId, frameQueryParams(), appviewxEnvironmentIsHTTPS)
	payload := frameDownloadKeyPayload(uuid, downloadPassword)
	requestBody, err := json.Marshal(payload)
	if err != nil {
		log.Println("[ERROR] error in Marshalling the payload ", payload, err)
		return false
	}
	client := &http.Client{Transport: HTTPTransport()}

	printRequest(httpMethod, url, headers, requestBody)

	req, err := http.NewRequest(httpMethod, url, bytes.NewBuffer(requestBody))
	if err != nil {
		log.Println("[ERROR] error in creating new Request", err)
		return false
	}

	for key, value := range headers {
		value1 := fmt.Sprintf("%v", value)
		key1 := fmt.Sprintf("%v", key)
		req.Header.Add(key1, value1)
	}
	if appviewxSessionID != "" {
		req.Header.Add(constants.SESSION_ID, appviewxSessionID)
	} else {
		req.Header.Add(constants.TOKEN, appviewxAccessToken)
	}
	httpResponse, err := client.Do(req)
	if err != nil {
		log.Println("[ERROR] error in http request", err)
		return false
	} else {
		log.Println("[INFO] Request for downloading the private submitted successfully")
	}
	log.Println("[INFO] Response status code : ", httpResponse.Status)
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		responseBody, err := io.ReadAll(httpResponse.Body)
		if err == nil {
			log.Println("[ERROR] Response obtained : ", string(responseBody))
			return false
		}
	}
	if responseByte, err = io.ReadAll(httpResponse.Body); err != nil {
		log.Println("[ERROR] Error while obtaining the response due to : ", err)
		return false
	}
	if err = json.Unmarshal(responseByte, &response); err != nil {
		log.Println("[ERROR] Error while obtaining the response due to : ", err)
		return false
	} else if response.AppviewxResponse.Status == "Success" {
		if downloadPasswordProtectedKey {
			log.Println("[INFO] Downloading the password protected private key file content. Kindly use the password provided in the .tf file")
			if err := writeKeyToFile(downloadPath, []byte(response.AppviewxResponse.PrivateKey)); err != nil {
				return false
			}
		} else {
			if err := decryptPasswordProtectedKeyAndDownloadKey(response.AppviewxResponse.PrivateKey, downloadPassword, downloadPath); err != nil {
				return false
			}
		}
	} else {
		log.Println("[ERROR] Error while obtaining the response due to : ", err)
		return false
	}
	return true
}

func decryptPasswordProtectedKeyAndDownloadKey(encryptedPrivateKey, password string, downloadPath string) error {
	log.Println("[INFO] Decrypting the password protected private key file content")
	tempFile := filepath.Join(os.TempDir(), "temp_private_key.pem")
	var file *os.File
	var err error
	file, err = os.Create(tempFile)
	if err != nil {
		fmt.Println("Error creating temp file:", err)
		return errors.New("error while decrypting the private key file content")
	}
	defer file.Close()
	defer os.Remove(tempFile)

	_, err = file.WriteString(encryptedPrivateKey)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return errors.New("error while decrypting the private key file content")
	}
	cmd := exec.Command("openssl", "pkey", "-in", tempFile, "-out", downloadPath, "-passin", "pass:"+password)

	err = cmd.Run()
	if err != nil {
		log.Printf("[ERROR] Error executing OpenSSL command: %v\n", err)
		return errors.New("error while decrypting the private key file content")
	}
	log.Println("[INFO] Private key decrypted successfully and saved in the specified path")
	return nil
}

func writeKeyToFile(downloadPath string, fileContent []byte) error {
	if err := os.WriteFile(downloadPath, fileContent, 0777); err != nil {
		log.Println("[ERROR] Error while downloading the private key file content in ", downloadPath, " due to : ", err)
		return errors.New("[ERROR] Error while downloading the private key file content in " + downloadPath + " due to : " + err.Error())
	} else {
		log.Println("[INFO] Downloaded private key file and available in ", downloadPath)
		return nil
	}
}

func searchCertificate(resourceID, appviewxSessionID, accessToken string, configAppViewXEnvironment *config.AppViewXEnvironment) config.AppviewxSearchCertResponse {
	var response config.AppviewxSearchCertResponse
	httpMethod := config.HTTPMethodPost
	appviewxEnvironmentIP := configAppViewXEnvironment.AppViewXEnvironmentIP
	appviewxEnvironmentPort := configAppViewXEnvironment.AppViewXEnvironmentPort
	appviewxEnvironmentIsHTTPS := configAppViewXEnvironment.AppViewXIsHTTPS
	headers := frameHeaders()
	url := GetURL(appviewxEnvironmentIP, appviewxEnvironmentPort, config.SearchCertificateActionId, frameQueryParams(), appviewxEnvironmentIsHTTPS)
	payload := frameSearchCertificatePayload(resourceID)
	requestBody, err := json.Marshal(payload)
	if err != nil {
		log.Println("[ERROR] error in Marshalling the payload ", payload, err)
		return response
	}
	client := &http.Client{Transport: HTTPTransport()}

	printRequest(httpMethod, url, headers, requestBody)

	req, err := http.NewRequest(httpMethod, url, bytes.NewBuffer(requestBody))
	if err != nil {
		log.Println("[ERROR] error in creating new Request", err)
		return response
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
		log.Println("[ERROR] error in http request", err)
		return response
	}
	log.Println("[INFO] Response status code : ", httpResponse.Status)
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		responseBody, err := io.ReadAll(httpResponse.Body)
		if err == nil {
			log.Println("[ERROR] Response obtained : ", string(responseBody))
			return response
		}
	}
	responseByte, err := io.ReadAll(httpResponse.Body)
	if err != nil {
		log.Println(err)
	} else {
		err = json.Unmarshal(responseByte, &response)
		if err != nil {
			log.Println("[ERROR] Error while searching for certificate with resource id "+resourceID+" due to :", err)
		} else {
			log.Println("[INFO] Obtained response for certificate search successfully")
		}
	}
	return response
}

func frameSearchCertificatePayload(resourceId string) config.SearchCertificatePayload {
	var payload config.SearchCertificatePayload
	payload.Filter.SortOrder = "asc"
	payload.Input.ResourceId = resourceId
	return payload
}

func frameDownloadCertificatePayload(appviewxResourceId, commonName, serialNumber, format, password string, isChainRequired bool) config.DownloadCertificatePayload {
	var payload config.DownloadCertificatePayload
	payload.CommonName = commonName
	payload.SerialNumber = serialNumber
	payload.Format = format
	payload.IsChainRequired = isChainRequired
	payload.Password = password
	payload.ResourceId = appviewxResourceId
	return payload
}

func frameDownloadKeyPayload(appviewxUUID, password string) config.DownloadKeyPayload {
	var payload config.DownloadKeyPayload
	payload.Password = password
	payload.UUID = appviewxUUID
	return payload
}
