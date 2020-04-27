# New-AzSecureApiManagement

Creates a new secure API Management behind an Application Gateway with Web Application Firewall enabled.

## Scenario

In most cases, an organization requires to publish internal APIs through Azure API Management. However, setting up an Application Gateway to protect the API Management resources can be complicated and time-consuming.

The aim of this setup is to automate the process of environment creation, according to the best practices in security, management, and cost optimization.

## Architecture

![Basic Architecture](/Images/SecureMicroservices.png)

## Design Highlights

* The environment will exist in a new Virtual Network. This is simply because of how complicated it would be to adopt an existing VNet for the setup. There are 3 subnet which will be created:
  * **Backend subnet**: Intended for hosting any backend services which shall be exposed using API Management, or Application Gateway
  * **APIM subnet**: Hosts the Azure API Management resource
  * **Frontend subnet**: Hosts the Application Gateway resource
* The Key Vault resource hosts the certificates, there are 3 different scenarios which this script supports
  * **Using self-signed certificates**: For development purposes, you might want to rely on Key Vault for self-signing the two certificates for this setup
  * **Using Certificates from a public well-known CA**: For production environment where the APIs are intended to be used externally. For example, in cases when the APIs and the APIM development portal are to be used by third-parties, mobile or web applications, and access publicly
  * **Using Certificates from a private CA**: For development or production environments where the APIs are intended to be used internally. Such as in internal application, or consumption via a tool which trusts the same CA
* The API Management resource is setup in either *Internal* or *External* VPN Types. For more information about the difference between the two, please refer to this [docs article](https://docs.microsoft.com/en-us/azure/api-management/api-management-using-with-internal-vnet)

## Resources

This setup will create the following resources

* Resource Group (Optional, you can use your existing resource group)
* Virtual network with three subnets
* Network Security Group for each of the subnets, configured with the proper rules to allow typical traffic patterns
* Key Vault for storing certificates used in the environment
* API Management (either Internal or External), connected to the APIM Subnet, and with Custom Domain configuration and certificates saved in Key Vault
* Public IP Address to recieve traffic from the internet
* Application Gateway with Web Application Firewall component. The Application Gateway is configured to proxy traffic listened for on the Public IP Address with the specified hostnames to the API Management backend
* Application Gateway User Managed Identity, to allow the Application Gateway to grab certificates from Key Vault

## Examples

* Create a new environment using self-signed certificates, these are created and signed by Key Vault. This is not recommended for a production environment.

```powershell
New-AzSecureApiManagement -ResourceGroupName "MyResouceGroup" -Location "WestEurope" -EnvironmentName "MyNewEnvironment" -VirtualNetworkCidr "10.0.1.0/23" -BackendSubnetCidr "10.0.1.0/24" -FrontendSubnetCidr "10.0.2.0/26" -ApimSubnetCidr "10.0.2.64/26" -ApimOrganizationName "MyOrganization" -ApimOrganizationEmail "myorg@email.com" -ApimSku "Developer" -ApimVpnType "Internal" -UseSelfSignedCertificates -ApimGatewayHostname "api.contoso.net" -ApimPortalHostname "portal.contoso.net" -IsWellKnownCA
```

* Create a new environment using custom certificates purchased from a well-know CA (i.e. Thawte or Digicert or any other well-known CA).

```powershell
New-AzSecureApiManagement -ResourceGroupName "MyResouceGroup" -Location "WestEurope" -EnvironmentName "MyNewEnvironment" -VirtualNetworkCidr "10.0.1.0/23" -BackendSubnetCidr "10.0.1.0/24" -FrontendSubnetCidr "10.0.2.0/26" -ApimSubnetCidr "10.0.2.64/26" -ApimOrganizationName "MyOrganization" -ApimOrganizationEmail "myorg@email.com" -ApimSku "Developer" -ApimVpnType "External" -ApimGatewayHostname "api.contoso.net" -ApimPortalHostname "portal.contoso.net" -IsWellKnownCA -GatewayCertificate "gatewaycertificate.pfx" -GatewayCertificatePassword (ConvertTo-SecureString -AsPlainText -String "certpassword") -PortalCertificate "portalcertificate.pfx" -PortalCertificatePassword (ConvertTo-SecureString -AsPlainText -String "certpassword")
```

* Create a new environment using custom certificates purchased a privately owned CA.

```powershell
New-AzSecureApiManagement -ResourceGroupName "MyResouceGroup" -Location "WestEurope" -EnvironmentName "MyNewEnvironment" -VirtualNetworkCidr "10.0.1.0/23" -BackendSubnetCidr "10.0.1.0/24" -FrontendSubnetCidr "10.0.2.0/26" -ApimSubnetCidr "10.0.2.64/26" -ApimOrganizationName "MyOrganization" -ApimOrganizationEmail "myorg@email.com" -ApimSku "Developer" -ApimVpnType "Internal" -ApimGatewayHostname "api.contoso.net" -ApimPortalHostname "portal.contoso.net" -CACertificate "cacert.cer" -GatewayCertificate "gatewaycertificate.pfx" -GatewayCertificatePassword (ConvertTo-SecureString -AsPlainText -String "certpassword") -PortalCertificate "portalcertificate.pfx" -PortalCertificatePassword (ConvertTo-SecureString -AsPlainText -String "certpassword")
```

## To-do List

* Create ARM Template to install the same setup using ARM
* Create az cli script to install the same setup (currently blocked by az apim module not being ready)
* Add functionality for installing Kubernetes in the backend subnet
* Add functionality for installing monitoring services (Application Insights and Log Analytics)
* Add better error handling, debugging information
* Add functionality for mTLS scenarios with the backend
