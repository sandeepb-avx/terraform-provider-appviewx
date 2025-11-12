# Certificate Download

The `appviewx_download_certificate` resource allows you to download an existing certificate from the AppViewX platform. This resource provides flexibility to retrieve certificates based on their name and save them to a specified location in the desired format.

## Process Overview

1. **Input Parameters**:
   - The resource accepts parameters such as `common_name`, `serial_number`, `resource_id`, `certificate_download_path`, `certificate_download_format`, `certificate_download_password`, and `certificate_chain_required`. These parameters are used to identify and download the certificate.

2. **Certificate Retrieval**:
   - When the resource is applied, it sends a request to the AppViewX API to retrieve the certificate based on the provided parameters like `common_name` and `serial_number` or `resource_id`.

3. **Certificate Download**:
   - The certificate is downloaded to the specified path in the desired format (e.g., `PEM`, `DER`, `P12`). Additional options like password-protecting the file are also supported.


## Attributes
The appviewx_download_certificate resource supports the following attributes:

### Required Attributes
- **`resource_id`** (string): The unique identifier of the certificate to be downloaded. This is typically obtained from the appviewx_create_certificate resource. This resource_id would have been printed in the logs when the `appviewx_create_certificate` resource is applied.
- **`common_name`** (string): The common name (CN) of the certificate, typically representing the domain name or entity associated with the certificate.
- **`serial_number`** (string): The serial number (SN) of the certificate, a unique identifier assigned by the certificate authority.

> **Note**: Either `resource_id` or a combination of `common_name` and `serial_number` must be provided to identify the certificate.

### Optional Attributes

- **`certificate_download_path`** (string): The file path to download the certificate.
- **`certificate_download_format`** (string): The format of the downloaded certificate. Possible values are PEM, CER, CRT, DER, P12, PFX
- **`certificate_download_password`** (string): The password for the downloaded certificate file. If this password is defined in the provider configuration, it takes precedence over the resource-level password. Additionally, when specified in the provider, the password will not be stored in the Terraform state file for enhanced security.
- **`certificate_chain_required`** (boolean): Whether to include the certificate chain in the downloaded certificate.

- **`key_download_path`** (string): The file path to download the private key seperately.
- **`key_download_password`** (string): The password for the downloaded private key. This is required to download the private key from AppViewX and by default the key is password protected from AppViewX.  If this password is defined in the provider configuration, it takes precedence over the resource-level password. Additionally, when specified in the provider, the password will not be stored in the Terraform state file for enhanced security.
- **`download_password_protected_key`** (boolean): To specify whether the private key should be downloaded as password-protected or plain private key. If this is enabled then the password protected key is downloaded as such, but if this is disabled then the password protected key is decrypted using the provided password using openssl and saved in the specified path automatically.
> **Note**: This Key download is optional and can be ignored if the certificate download format specified is P12 or PFX.


## Example Usage
```hcl
resource "appviewx_download_certificate" "example" {
   common_name                  = "sample.example.com"
   serial_number                = "serial_number_of_certificate"
   certificate_download_path    = "/path/to/directory"
   certificate_download_format  = "PEM"
   certificate_download_password = "password"
   certificate_chain_required   = true
   key_download_path          = "/path/to/directory"
   key_download_password      = "password"
   download_password_protected_key = false
}
```
> **Note**: This `appviewx_download_certificate` resource can be used to download the same or different certificates multiple times.

## Import

To import an existing certificate into the Terraform state, use the following command:

```bash
terraform import appviewx_download_certificate.downloadcert <resource_id>
```

Replace `<resource_id>` with the actual resource ID of the certificate you want to import.

