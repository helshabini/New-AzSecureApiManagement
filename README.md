# New-AzSecureApiManagement

Creates a new secure API Management behind an Application Gateway with Web Application Firewall enabled.

![Basic Architecture](/Images/SecureMicroservices.png)

## This setup will create the following resources

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
* Add functionality for installing Kubernetes in the backend subnet
