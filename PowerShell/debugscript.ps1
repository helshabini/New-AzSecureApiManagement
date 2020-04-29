Get-Location
Import-Module .\PowerShell\New-AzSecureApiManagement.psm1
New-AzSecureApiManagement -ResourceGroupName "newrg" -Location "WestEurope" -EnvironmentName "haenv" -ApimOrganizationName "MyOrganization" -ApimOrganizationEmail "myorg@email.com" -UseSelfSignedCertificates -ApimGatewayHostname "api.contoso.net" -ApimPortalHostname "portal.contoso.net"