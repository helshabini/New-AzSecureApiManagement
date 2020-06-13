Get-Location
Get-Module -Name New-AzSecureApiManagement | Remove-Module -Force
Import-Module .\PowerShell\New-AzSecureApiManagement.psm1
New-SecureAzApiManagementSelfSignedCerts -Country "US" -State "WA" -City "Redmond" -Company "fawzytech.com" -Department "IT" -GatewayHostname "api.fawzytech.com" -PortalHostname "portal.fawzytech.com" -GatewayCertificatePassword "certpassword" -PortalCertificatePassword "certpassword"
New-AzSecureApiManagement -ResourceGroupName "newrg" -Location "WestEurope" -EnvironmentName "haelshabsecapim" -VirtualNetworkCidr "10.0.0.0/23" -BackendSubnetCidr "10.0.0.0/24" -FrontendSubnetCidr "10.0.1.0/26" -ApimSubnetCidr "10.0.1.64/26" -ApimOrganizationName "Fawzytech" -ApimOrganizationEmail "h.elshabini@outlook.com" -ApimSku "Developer" -ApimVpnType "Internal" -ApimGatewayHostname "api.fawzytech.com" -ApimPortalHostname "portal.fawzytech.com" -CACertificate "cacert.cer" -GatewayCertificate "api.pfx" -GatewayCertificatePassword (ConvertTo-SecureString -AsPlainText -String "certpassword") -PortalCertificate "portal.pfx" -PortalCertificatePassword (ConvertTo-SecureString -AsPlainText -String "certpassword")

# Start-Sleep 10

# $ResourceGroupName = "newrg1"
# $apimname = "apim-haelshabsecapim7175"
# $keyvaultname = "kv-haelshabsecapim7175"
# $ApimGatewayHostname = "api.fawzytech.com"
# $ApimPortalHostname = "portal.fawzytech.com"
# $gatewaycertname = "haelshabsecapim7175GatewayCert"
# $portalcertname = "haelshabsecapim7175PortalCert"

# Write-Host "Getting reference to Key Vault certificates"
#                 $gatewaycert = Get-AzKeyVaultCertificate -VaultName $keyvaultname -Name $gatewaycertname
#                 $portalcert = Get-AzKeyVaultCertificate -VaultName $keyvaultname -Name $portalcertname
#                 Write-Host "Getting Secret Id for certificate access"
#                 $gatewaycertsecretid = $gatewaycert.SecretId.Replace($gatewaycert.Version, "")
#                 $portalcertsecretid = $portalcert.SecretId.Replace($portalcert.Version, "")

#         $apim = Get-AzApiManagement -ResourceGroupName $ResourceGroupName -Name $apimname

#         Write-Host "Assinging key vault access policy for APIM System Assigned Managed Identity"
#         Set-AzKeyVaultAccessPolicy `
#             -VaultName $keyvaultname `
#             -PermissionsToSecrets get `
#             -PermissionsToCertificates get,create,list `
#             -ObjectId $apim.Identity.PrincipalId

#         Start-Sleep 3

#         Write-Host "Creating hostname configuration for the gateway and portal"
#         $apimgatewayostnameconfig = New-AzApiManagementCustomHostnameConfiguration `
#             -Hostname $ApimGatewayHostname `
#             -HostnameType Proxy `
#             -KeyVaultId $gatewaycertsecretid
#         $apimportalhostnameconfig = New-AzApiManagementCustomHostnameConfiguration `
#             -Hostname $ApimPortalHostname `
#             -HostnameType DeveloperPortal `
#             -KeyVaultId $portalcertsecretid

#         Start-Sleep 3

#         Write-Host "Setting hostname configuration on the APIM"
#         $apim.ProxyCustomHostnameConfiguration = $apimgatewayostnameconfig
#         $apim.PortalCustomHostnameConfiguration = $apimportalhostnameconfig

#         Write-Host "Applying configuration for APIM"
#         Set-AzApiManagement -InputObject $apim

#         $apim = Get-AzApiManagement -ResourceGroupName $ResourceGroupName -Name $apimname

#         Start-Sleep 10