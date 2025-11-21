# Certificate Creation and Push to Azure Key Vault

The `appviewx_certificate_push_akv` resource automates the creation of a certificate and its push to Azure Key Vault (AKV) using AppViewX workflows.

## Prerequisites

- **`Necessary permissions to delete the Certificate and the associated Key in Azure Key Vault`**
- **`Azure Key Vault (AKV) need to be onboarded in AppViewX`**
- **`This Terraform version(tf) can be used only when there is a custom workflow enabled for pushing certs to AKV`**

## Process Overview

1. **Input Parameters**:
   - The resource accepts a single required parameter, `field_info`, which is a JSON string containing all certificate and key vault configuration details. This includes certificate subject details, key parameters, CA settings, and Azure Key Vault information.

2. **Workflow Execution**:
   - The resource triggers a pre-configured AppViewX Custom workflow to create and push the certificate to AKV.

3. **Authentication**:
   - Authentication to AppViewX can be performed using either username/password or client ID/secret, provided via provider configuration or environment variables.

4. **Response Handling**:
   - The resource captures the workflow request ID, HTTP status code, and whether the request was successful. The workflow ID can be used to poll for status and download the certificate using the `appviewx_create_push_certificate_request_status` resource.

5. **State Management**:
   - The resource is create-only. Updates and deletes simply remove the resource from Terraform state.

## Attributes

### Required Attributes

- **`field_info`** (string, sensitive):  
  JSON string containing all certificate and key vault configuration.  

- **`workflow_name`** (string):  
  The custom workflow name to execute the Create Certificate and Push to AKV Operation.

### NOTE:
- These mandatory and optional attributes might differ based on the custom workflow used in AppViewX.

### Mandatory parameters

- **`certificate_group_name`** (string): The name of the group to which the certificate belongs in AppViewX.

- **`azure_account_name`** (string): The name of the AKV Device which was onboarded in AppViewX.

- **`azure_key_vault_name`** (string): The name of the AKV Key Vault which was onboarded in AppViewX.

- **`certificate_type`** (string): Describes the Certificate category. Possible Values: [`Server`, `Client`, `CodeSigning`]

- **`certificate_authority`** (string): The name of the Certificate Authority (CA) to issue the certificate. Possible Values: [`AppViewX`, `Sectigo`, `OpenTrust`, `Microsoft Enterprise`, `DigiCert`]

- **`validity_unit`** (string): The unit of validity for the certificate. Possible values are [`Days`, `Months`, `Years`].

- **`validity_unit_value`** (string): The value for the validity unit

- **`common_name`** (string): The domain name or identifier for the certificate.

- **`hash_algorithm`** (string): Describes the Hashing algorithm. Possible Values are [`SHA160`, `SHA224`, `SHA256`, `SHA384`, `SHA512`, `SHA3-224`, `SHA3-256`]

- **`key_type`** (string): The cryptographic algorithm for the key. Possible values are [`RSA`, `DSA`, `EC`]

- **`key_bit_length`** (string): The size of the key in bits. Possible values are 
  - RSA : [`1024`, `2048`, `3072`, `4096`, `7680`, `8192`].
  - DSA : [`1024`, `2048`].
  - EC : [`160`, `163`, `191`, `192`, `193`, `224`, `233`, `239`, `256`, `283`, `320`, `359`, `384`, `409`, `431`, `512`, `521`, `571`]
  - ECDSA Curve : [`ECDSA Curve that appviewx is supporting`]

## Example Usage

### Certificate Creation with AppViewX CA

```hcl
provider "appviewx" {
  appviewx_environment_ip = "<AppViewX - FQDN or IP>"
  appviewx_environment_port = "<Port>"
  appviewx_environment_is_https = true
}

resource "appviewx_certificate_push_akv" "<Common Name and AKV name or any unique string can be given as a resource name>" {
  field_info = jsonencode({
    "certificate_group_name": "Group1",
    "azure_account_name": "AKV",
    "azure_key_vault_name": "KeyVault",
    "certificate_type": "Server",
    "certificate_authority": "AppViewX Certificate Authority",
    "validity_unit": "Days",
    "validity_unit_value": "4",
    "common_name": "appviewxCertificate.xxxxx.yy",
    "hash_algorithm": "SHA256",
    "key_type": "RSA",
    "key_bit_length": "2048"
  })
  workflow_name = "Create Cert Workflow"

  resource "appviewx_create_push_certificate_request_status" "<Common Name and AKV name or any unique string can be given as a resource name>" {
  request_id = appviewx_certificate_push_akv.<Common Name and AKV name or any unique string can be given as a resource name>.workflow_id
  retry_count = 20
  retry_interval = 20
  depends_on = [appviewx_certificate_push_akv.<Common Name and AKV name or any unique string can be given as a resource name>]
}
}
```

## Response of the Resource

Response of the appviewx_certificate_push_akv resource

```bash
{
  "response": {
    "workorderId": "0",
    "requestType": "sample",
    "requestId": "2642",
    "workflowVersion": "version1",
    "message": "Workflow Request is created with Id 2642 . Request submitted to workflow engine for processing workorder.",
    "status": "In Progress",
    "statusCode": 0
  },
  "message": "Success",
  "appStatusCode": null,
  "tags": null,
  "headers": {
    "X-WorkFlowName": "Create Certificate Push to AKV"
  }

```

Final Response of this Request after pooling the Status of the Certificate Creation and pushing to AKV process

```bash
[CERTIFICATE CREATION][SUCCESS] ✅ Operation Result:
{
  "completed_at": "<Timestamp>",
  "operation": "Certificate Creation and Push",
  "status": "Successful",
  "status_code": 1,
  "workflow_id": "2645"
}
```
## Destroy

### Resource Naming Convention

**Resource Type (Non-Modifiable)**:
```hcl
resource "appviewx_certificate_push_akv" "webapp_example_com_production_akv" {
```
- `appviewx_certificate_push_akv` is the resource type and **cannot be modified**. The certificate creation process depends on this specific resource type name.

**Resource Name (Modifiable)**:
```hcl
resource "appviewx_certificate_push_akv" "webapp_example_com_production_akv" {
```
- `webapp_example_com_production_akv` is the resource name and is **fully customizable**. You can define any unique name according to your preference. This name will be reflected in the Terraform state file.

**Recommended Naming Convention**:
We recommend creating a unique resource name by combining the certificate common name and the Azure Key Vault device name. For example:
- Certificate Common Name: `webapp.example.com`
- AKV Device Name: `production-akv`
- Resource Name: `webapp_example_com_production_akv`

This naming convention helps easily identify and manage specific certificates when performing destroy operations.

### Destroying Resources

When you destroy a resource using the commands below, the following operations are performed:
1. Remove the resource from the Terraform state file
2. Revoke the certificate
3. Delete the certificate from Azure Key Vault (AKV)

**Step 1: List Available Resources**

Before destroying, list the resources in your state file:

```bash
terraform state list
```

Expected output:
```
appviewx_certificate_push_akv.<your_resource_name>
appviewx_create_push_certificate_request_status.<your_resource_name>
```

**Step 2: Destroy Specific Resources**

To destroy a specific certificate and its associated status resource, use the targeted destroy command:

```bash
terraform destroy \
  -target='appviewx_certificate_push_akv.<your_resource_name>' \
  -target='appviewx_create_push_certificate_request_status.<your_resource_name>'
```

Replace `<your_resource_name>` with the actual resource name you defined in your Terraform configuration.

**Note**: 
- This targeted destroy ensures only the specified certificate resources are removed, revoked, and deleted.

---