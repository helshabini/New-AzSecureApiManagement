Get-Location
Import-Module .\PowerShell\New-AzSecureApiManagement.psm1
New-AzSecureApiManagement -ResourceGroupName "newrg4" -Location "WestEurope" -EnvironmentName "haenv4" -ApimOrganizationName "MyOrganization" -ApimOrganizationEmail "myorg@email.com" -UseSelfSignedCertificates -ApimGatewayHostname "api.contoso.net" -ApimPortalHostname "portal.contoso.net"