package config

type DownloadCertificatePayload struct {
	CommonName      string `json:"commonName"`
	SerialNumber    string `json:"serialNumber"`
	Format          string `json:"format"`
	Password        string `json:"password"`
	IsChainRequired bool   `json:"isChainRequired"`
	ResourceId      string `json:"resourceId"`
}

type DownloadKeyPayload struct {
	Password string `json:"password"`
	UUID     string `json:"uuId"`
}

type SearchCertificatePayload struct {
	Input  Input  `json:"input"`
	Filter Filter `json:"filter"`
}

type Input struct {
	ResourceId   string `json:"resourceId,omitempty"`
	CommonName   string `json:"commonName,omitempty"`
	SerialNumber string `json:"serialNumber,omitempty"`
}

type Filter struct {
	SortOrder string `json:"sortOrder"`
}

type AppviewxSearchCertResponse struct {
	AppviewxResponse CertificateResponse `json:"response"`
	Message          string              `json:"message"`
	AppStatusCode    string              `json:"appStatusCode"`
	Tags             map[string]string   `json:"tags"`
	Headers          string              `json:"headers"`
}

type CertificateResponse struct {
	ResponseObject CertificateObjects `json:"response"`
}

type CertificateObjects struct {
	Objects []CertificateDetails `json:"objects"`
}

type CertificateDetails struct {
	CommonName   string `json:"commonName"`
	SerialNumber string `json:"serialNumber"`
	UUID         string `json:"uuid"`
}

type AppviewxDownloadKeyResponse struct {
	AppviewxResponse DownloadKeyResponse `json:"response"`
	Message          string              `json:"message"`
	AppStatusCode    string              `json:"appStatusCode"`
	Tags             map[string]string   `json:"tags"`
	Headers          string              `json:"headers"`
}

type DownloadKeyResponse struct {
	PrivateKey string `json:"privateKeyPemEncoded"`
	Status     string `json:"status"`
}

var DownloadCertificateActionId = "certificate/download/format"
var SearchCertificateActionId = "certificate/search"
var DownloadKeyActionId = "certificate/privatekey/download"
