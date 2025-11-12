# terraform-provider-appviewx

## Build
```
> cd ../terraform-provider-appviewx
> go build -o terraform-provider-appviewx
```

## Enable logs  ( TRACE, DEBUG, INFO, WARN or ERROR )
```
> export TF_LOG=TRACE
```

## Sample ' version.tf ' file
```
terraform {
  required_providers {
    appviewx = {
      version = "1.0.1"
      source  = "appviewx.com/provider/appviewx"
    }
  }
}
```
## Sample ' appviewx.tf'  file
```
provider "appviewx"{
    #Either username, password or clientid,secret can be provided
    appviewx_username="USER_NAME"
    appviewx_password="PASSWORD"
    appviewx_client_id="CLIENT_ID"
    appviewx_client_secret="CLIENT_SECRET"
    appviewx_environment_is_https=true
    appviewx_environment_ip="APPVIEWX_HOST_NAME"
    appviewx_environment_port="APPVIEWX_PORT_NUMBER"
    certificate_download_password="<Password to save the certificate with types P12,JKS and PFX>"
    key_download_password="<Password to save the private key>"
}

resource "appviewx_create_certificate" "createcert"{
    common_name="<Common name>"
    hash_function="<Hash function>"
    key_type="<Key type>"
    bit_length="<Bit length>"
    certificate_authority="<CA NAME>"
    ca_setting_name="<CA Setting name added in Appviewx UI>"
    certificate_type="<Certificate Type if any specific to CA>"
    dns_names=["domain.com","domain12.com"]
    custom_fields={"field_name":"value"}
    vendor_specific_fields={"fielname":"value"}
    validity_unit="<days/months/years>"
    validity_unit_value=<Any validity value>
    certificate_group_name="<Group name where certificate will be created>"
    is_sync=true

    #if sync is true below fields are mandatory
    certificate_download_path="<Directory/filename where certificate to be downloaded>"
    certificate_download_format="<P12/PEM/CRT/DER/JKS/PFX>"
    certificate_download_password="<Mandatory for P12,JKS and PFX>"

    #If trust tore certificates to be included in the certificate which will be downloaded
    certificate_chain_required=true

    key_download_path="<Directory/filename where private key to be downloaded>" #Key download related fields are optional
    key_download_password="<Mandatory to download private key>"

    #If download_password_protected_key is true then key will be downloaded as a password #protected key which can be used with the password specified in field key_download_password
    download_password_protected_key=false
}

resource "appviewx_download_certificate" "downloadcert"{
	  #Either resource_id or common_name and serial_number can be provided to download the cert/key
    resource_id="<ResourceID obtained if is_sync is false>"
    common_name="<CN of the certificate if known>"
    serial_number="<Serial number of the certificate if known>"
      
    certificate_download_path="<Directory/filename where certificate to be downloaded>"
    certificate_download_format="<P12/PEM/CRT/DER/JKS/PFX>"
    certificate_download_password="<Mandatory for P12,JKS and PFX>"

    key_download_path="<Directory/filename where private key to be downloaded>" #Key download related fields are optional
    key_download_password="<Mandatory to download private key>"

    #If download_password_protected_key is true then key will be downloaded as a password #protected key which can be used with the password specified in field key_download_password
    download_password_protected_key=false
    
}


```
## Sample ' createAndDownload.tf'  file
```
Both resources can be combined in a single .tf file as mentioned below

resource "appviewx_create_certificate" "createcert"{
	  common_name="<Common name>"
	  hash_function="<Hash function>"
    key_type="<Key type>"
    bit_length="<Bit length>"
    certificate_authority="<CA NAME>"
    ca_setting_name="<CA Setting name added in Appviewx UI>"
    certificate_type="<Certificate Type if any specific to CA>"
    dns_names=["domain.com","domain12.com"]
    custom_fields={"field_name":"value"}
    vendor_specific_fields={"fielname":"value"}
    validity_unit="<days/months/years>"
    validity_unit_value=<Any validity value>
    certificate_group_name="<Group name where certificate will be created>"
    is_sync=false
}

resource "time_sleep" "wait" {
    depends_on = [appviewx_create_certificate.createcert]
    create_duration = "10s" # Wait time can be configured based on the time taken by CA to issue the certificate
}

resource "appviewx_download_certificate" "downloadcert"{
	  depends_on = [time_sleep.wait]
	  resource_id=appviewx_create_certificate.createcert.resource_id
    #Here the resource id will be automatically fetched from the previous resource

    certificate_download_path="<Directory/filename where certificate to be downloaded>"
    certificate_download_format="<P12/PEM/CRT/DER/JKS/PFX>"
    certificate_download_password="<Mandatory for P12,JKS and PFX>"

    #If trust tore certificates to be included in the certificate which will be downloaded
    certificate_chain_required=true

    key_download_path="<Directory/filename where private key to be downloaded>" #Key download related fields are optional
    key_download_password="<Mandatory to download private key>"

    #If download_password_protected_key is true then key will be downloaded as a password #protected key which can be used with the password specified in field key_download_password
    download_password_protected_key=false
}

```
> **Note:** When the password is defined in both the provider and the resource, the value from the provider takes precedence.

## Steps to run
```
> Keep the .tf files in the current folder

> keep the "terraform-provider-appviewx" binary file under "~/.terraform.d/plugins/appviewx.com/provider/appviewx/<desired_provider_version>/<os_arch>"   ( eg: linux_386, darwin_amd64, etc)

> Run the following commands, to reset and trigger the request

	rm -rf ./terraform.tfstate;
	terraform init;
	terraform apply;