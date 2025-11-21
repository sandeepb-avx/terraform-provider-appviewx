# Certificate Push Workflow Status and Download

The `appviewx_create_push_certificate_request_status` resource is used to poll the status of a certificate creation and push workflow, and optionally download the certificate after successful completion.

## Process Overview

1. **Workflow Status Polling**:
   - The resource polls the status of a workflow using the `request_id` (workflow ID).
   - Polling is performed at configurable intervals and retry counts.

2. **Status and Logs**:
   - The resource captures the workflow status, status code, summary of all tasks, and detailed logs for any failed tasks.
   - If the workflow fails, the failure reason is extracted from the logs.

3. **Certificate Download**:
   - If `is_download_required` is set to `true` and the workflow is successful, the certificate is downloaded to the specified path in the desired format.
   - The certificate chain and password protection can be configured.

4. **Certificate Details**:
   - The resource can extract and store the certificate common name and serial number for further use.

## Attributes

### Required Attributes

- **`request_id`** (string): The workflow request ID.

### Optional Attributes

- **`retry_count`** (int):  
  Number of times to retry checking workflow status (default: 10).
  Reasonable values - 10 and above

- **`retry_interval`** (int):  
  Seconds to wait between retry attempts (default: 20).
  Reasonable values - 20 and above

- **`certificate_common_name`** (string):  
  Common name of the certificate (optional, for download naming).

- **`is_download_required`** (bool):  
  Whether to download the certificate after workflow completion (default: false).

- **`certificate_download_path`** (string):  
  Path to download the certificate.

- **`certificate_download_format`** (string):  
  Format for the downloaded certificate. Possible values are [PEM, CER, CRT, DER].

- **`certificate_chain_required`** (bool):  
  Whether to include the certificate chain in the download (default: true).

## Example Usage

```hcl
resource "appviewx_create_push_certificate_request_status" "<Common Name and AKV name or any unique string can be given as a resource name>" {
  request_id = "<Workflow Request ID>"
  retry_count = 30
  retry_interval = 15
  certificate_common_name = "<Common Name of the Certificate>"
  certificate_download_path = "</path/to/directory or /path/to/directory/filename>"
  certificate_download_format = "CRT"
  certificate_chain_required = true
  is_download_required = true
}
```

## Response

Final Response of this Request after pooling the Status of the Certificate Creation and pushing to AKV process

```bash
[CERTIFICATE CREATION][SUCCESS] ✅ Operation Result:
{
  "completed_at": "<Timestamp>",
  "operation": "Certificate Creation and Push",
  "status": "Successful",
  "status_code": 1,
  "workflow_id": "2021"
}
```

If you specified the Download is needed, the response will be as below

```bash
[CERTIFICATE CREATION][SUCCESS] ✅ Operation Result:
{
  "certificate_common_name": "aaa.xxx.yy",
  "certificate_download_path": "<Certificate downloaded path>",
  "completed_at": "<Timestamp>",
  "operation": "Certificate Creation and Push",
  "resource_id": "688kj4nk4nk4hrknvg",
  "status": "Successful",
  "status_code": 1,
  "workflow_id": "2022"
}
```

## Destroy

### Resource Naming Convention

**Resource Type (Non-Modifiable)**:
```hcl
resource "appviewx_create_push_certificate_request_status" "webapp_example_com_production_akv" {
```
- `appviewx_create_push_certificate_request_status` is the resource type and **cannot be modified**. The certificate status polling process depends on this specific resource type name.

**Resource Name (Modifiable)**:
```hcl
resource "appviewx_create_push_certificate_request_status" "webapp_example_com_production_akv" {
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
2. Revoke the certificate in AppViewX
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