# AppViewX Terraform Provider

[AppViewX](https://appviewx.com) protects many of the world’s brands with the industry’s most advanced cloud-native Certificate Lifecycle Management (CLM) and Public Key Infrastructure (PKI) platform. Our solutions safeguard customers and enable digital transformation in the largest and most security-conscious enterprise organizations globally.

**AVX ONE** is the industry’s most advanced and fastest growing cloud-native Certificate Lifecycle Management (CLM) platform. It provides a suite of market leading capabilities including Smart Discovery, Crypto Resilience Scorecard, Closed-looped Automation and Infrastructure Context Awareness.

Powered by the market’s only out-of-the-box workflow engine, AVX ONE allows customers to realize immediate value from complete certificate lifecycle management, enterprise-wide Kubernetes TLS automation, scalable PKI-as-a-Service, secure code signing, easy Microsoft CA migration, IoT security, SSH and key management, and PQC-forward controls in even the most complex multi-cloud, hybrid, and edge environments.

Seamlessly enforce enterprise policies and strict access controls, ensure cryptographic agility, and prevent attacks that exploit expired, rogue, and non-compliant digital certificate identities.

AppViewX Terraform Provider allows you to manage certificates using the AppViewX platform. This provider enables certificate creation and download through Terraform configurations.

## Requirements

- Terraform 1.0 or later
- AppViewX Service Account Credentials
- Configurations in AppViewX like Certificate Authority, Certificate Group, and Policy.

## Installation

1. Download the `terraform-provider-appviewx` binary from the [AppViweX Terraform GitHub](https://github.com/AppViewX/terraform-provider-appviewx).
2. Place the binary in your Terraform plugins directory.
3. Configure the provider in your Terraform configuration file.

## Provider Configuration

```hcl
provider "appviewx" {
    appviewx_username="username"
    appviewx_password="password"
    appviewx_client_id="clientid"
    appviewx_client_secret="clientsecret"
    appviewx_environment_is_https=true
    appviewx_environment_ip="appviewx_environment_ip or appviewx_environment_fqdn"
    appviewx_environment_port="appviewx_port"
    certificate_download_password="certificate_password"
    key_download_password="key_password"
    log_level="INFO"
}
```

## Atrributes

- `appviewx_username`:
    - The username used to authenticate with the AppViewX API.
    - This is provided by your AppViewX administrator.
    - **Environment Variable:** If not specified in the provider block, the value will be read from `APPVIEWX_TERRAFORM_USERNAME`.

- `appviewx_password`:
    - The password associated with the AppViewX username.
    - Used for secure authentication.
    - **Environment Variable:** If not specified in the provider block, the value will be read from `APPVIEWX_TERRAFORM_PASSWORD`.

- `appviewx_client_id`:
    - The client ID used to authenticate with the AppViewX API.
    - This is provided by your AppViewX administrator.
    - **Environment Variable:** If not specified in the provider block, the value will be read from `APPVIEWX_TERRAFORM_CLIENT_ID`.

- `appviewx_client_secret`:
    - The client secret associated with the client ID. This is used for secure authentication.
    - **Environment Variable:** If not specified in the provider block, the value will be read from `APPVIEWX_TERRAFORM_CLIENT_SECRET`.

- `appviewx_environment_is_https`:
    - A boolean value indicating whether the AppViewX environment uses HTTPS.
    - Set this to `true` if your environment is secured with HTTPS.

- `appviewx_environment_ip`:
    - The IP address or fully qualified domain name (FQDN) of the AppViewX environment.
    - Only the IP or FQDN should be provided, without any port or other values.
    - For on-premise AppViewX, use the IP or FQDN of the gateway.
    - For SaaS, provide the FQDN of the AppViewX Tenant.

- `appviewx_environment_port`:
    - The port number used to connect to the AppViewX environment.
    - Ensure this matches the port configured for API access.
    - For on-premise AppViewX, use `31443`.
    - For SaaS, use `443`.

- `certificate_download_password`:
    - The password used to download the created certificate or provided certificate details in formats such as P12 or PFX.
    - If specified in the provider block, the password will not be stored in the `.tfstate` file.
    - When the password is defined in both the provider and the resource, the value from the provider takes precedence.

- `key_download_password`:
    - The password used to download the private key associated with the certificate.
    - Similar to `certificate_download_password`, if specified in the provider block, it will not be stored in the `.tfstate` file.
    - If defined in both the provider and the resource, the value from the provider takes precedence.

- `log_level`:
    - Describes the log level.
    - Default is set to `INFO`.
    - Possible values are [`INFO`, `DEBUG`].

**Example environment variable usage:**
```sh
export APPVIEWX_TERRAFORM_CLIENT_ID="your_client_id"
export APPVIEWX_TERRAFORM_CLIENT_SECRET="your_client_secret"
export APPVIEWX_TERRAFORM_USERNAME="your_username"
export APPVIEWX_TERRAFORM_PASSWORD="your_password"
```

## Support
For support, please contact [AppViewX Support](https://helpcenter.appviewx.com/login)

## Certificate Management

The AppViewX Terraform Provider simplifies certificate management by enabling seamless integration with the AppViewX platform. Using this provider, you can automate the creation and retrieval of certificates, ensuring secure and efficient workflows for your infrastructure.

Below are the available certificate management operations:
- [Create Certificate](resources/appviewx_create_certificate.md)
- [Download Certificate](resources/appviewx_download_certificate.md)