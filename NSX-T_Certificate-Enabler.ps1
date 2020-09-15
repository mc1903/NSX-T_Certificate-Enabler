<#

The Official Home for this Project is https://github.com/mc1903/NSX-T_Certificate-Enabler

This script has been tested with the following applications/versions:
    
    VMware NSX-T v3.0.0.0.0.15945876
    
Version 1.00 - Martin Cooper 15/09/2020
    Initial Release.
    
#>

#Parameters
    [CmdletBinding(
        PositionalBinding = $false,
        DefaultParameterSetName = 'UsernameAndPassword'
    )]
    param (
        [Parameter(
            Position = 0,
            Mandatory = $true,
            HelpMessage = 'Please provide the FQDN of the first NSX-T Manager'
        )]
        [ValidateNotNullOrEmpty()]
        [String[]] $Server,

        [Parameter(
            Position = 1,
            Mandatory = $true,
            HelpMessage = 'Please provide a NSX-T Administrator Base64 Credential',
            ParameterSetName = 'Credential'
        )]
        [ValidateNotNullOrEmpty()]
        [String] $Credential,

        [Parameter(
            Position = 1,
            Mandatory = $true,
            HelpMessage = 'Please provide a NSX-T Administrator Username',
            ParameterSetName = 'UsernameAndPassword'
        )]
        [ValidateNotNullOrEmpty()]
        [String] $Username,

        [Parameter(
            Position = 2,
            Mandatory = $false,
            HelpMessage = 'Please provide a NSX-T Administrator Password',
            ParameterSetName = 'UsernameAndPassword'
        )]
        [String] $Password,

        [Parameter(
            Position = 3,
            Mandatory = $false,
            HelpMessage = 'Disable NSX-T Manager CRL Checking'
        )]
        [bool] $DisableCRLChecking = $false
    )

# If there is no Credential AND if no Password was entered, prompt for the Password
If (!$Credential) {
    If (!$Password) {
        $SecurePwd = Read-Host -Prompt "Please provide a NSX-T Administrator Password" -AsSecureString
        $Password =[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePwd))
    }
}

# If Username and Password parameters are used, convert specified Username and Password into a Base64 string and store in $Credential
If (($Username -and $Password)) {
    $Credential = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($Username):$($Password)"))
}

#Hide Errors
$Global:ProgressPreference = 'silentlyContinue'

#Functions
Function Test-NSXTMgrConnections {
    Param(
    [parameter(Mandatory=$true)]
    [String]
    $Hostname
    )

        #Confirm DNS resolution for NSX Manager
        Write-Host "`nTesting NSX-T Manager $($Hostname)`n"
        Try { $DNSTest = Resolve-DNSName -Name $Hostname -ErrorAction Stop
                } 
            Catch
                {
                    Write-Host "`tError $($Hostname) does NOT resolve via DNS" -ForegroundColor Red
                    Exit
                }
            Finally
                {
                    If ($DNSTest.IP4Address) {
                    Write-Host "`t$($Hostname) resolves to $($DNSTest.IP4Address)" -ForegroundColor Green
                    }
                    If ($DNSTest.NameHost) {
                    Write-Host "`t$($Hostname) resolves to $($DNSTest.NameHost)" -ForegroundColor Green
                    }
                }
  
        #Confirm ICMP & Port 443 Connectivity for NSX Manager
        $IPConnTest = Test-NetConnection -ComputerName $Hostname -Port 443 -ErrorAction Stop -WarningAction SilentlyContinue
            If ($IPConnTest.PingSucceeded -eq $false) {
                Write-Host "`t$($Hostname) DOES NOT respond to PING" -ForegroundColor Red
            }
            If ($IPConnTest.TcpTestSucceeded -eq $false) {
                Write-Host "`t$($Hostname) DOES NOT respond on HTTPS/443" -ForegroundColor Red
            }
            If ($IPConnTest.PingSucceeded -eq $true) {
                Write-Host "`t$($Hostname) responds to PING" -ForegroundColor Green
            }
            If ($IPConnTest.TcpTestSucceeded -eq $true) {
                Write-Host "`t$($Hostname) responds on HTTPS/443" -ForegroundColor Green
            }
        
}

#By default NSX Manager 3.x will only accept TLS 1.1 & 1.2 connections
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls11;

#Trust/Ignore Self Signed Certificates
Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
    ServicePoint srvPoint, X509Certificate certificate,
    WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

#Clear the output display
Clear-Host

#Test Connectivity to the NSX Managers
$NSXTCluster = Invoke-Restmethod -Method GET -Uri "https://$Server/api/v1/cluster" -Headers @{ Authorization = "Basic $($Credential)" } | Select-Object -ExpandProperty nodes
    ForEach ($NSXMgr in $NSXTCluster) {
        Test-NSXTMgrConnections $($NSXMgr.FQDN)
    }

#Get the NSXT Cluster Status. Exit if the overall status is NOT Stable!
Write-Host "`nChecking NSX-T Cluster Status`n"
$NSXTClusterStatus = Invoke-Restmethod -Method GET -Uri "https://$Server/api/v1/cluster/status" -Headers @{ Authorization = "Basic $($Credential)" }
    If ($NSXTClusterStatus.detailed_cluster_status.overall_status -ne "STABLE") {
        Write-Host "`tThe NSX-T Manager Cluster is in a $($NSXTClusterStatus.detailed_cluster_status.overall_status) state" -ForegroundColor Red
        Write-Host "`tPlease review and fix this. Unable to continue!" -ForegroundColor Red
        Exit
    }
    Else {
        Write-Host "`tThe NSX-T Manager Cluster is in a $($NSXTClusterStatus.detailed_cluster_status.overall_status) state" -ForegroundColor Green
        Write-Host "`t`tThe Cluster ID is $($NSXTClusterStatus.cluster_id)" -ForegroundColor Yellow
    }

#Get each NSX-T Manager Version
Write-Host "`nChecking NSX-T Manager Versions`n"
    ForEach ($NSXTMgr in $NSXTCluster) {
        $NSXTMgrVersion = Invoke-Restmethod -Method GET -Uri "https://$($NSXTMgr.FQDN)/api/v1/node/version" -Headers @{ Authorization = "Basic $($Credential)" }
        Write-Host "`t$($NSXTMgr.FQDN)" -ForegroundColor Green
        Write-Host "`t`tNode version $($NSXTMgrVersion.node_version)" -ForegroundColor Yellow
        Write-Host "`t`tProduct version $($NSXTMgrVersion.product_version)`n" -ForegroundColor Yellow
    }

#Get the NSX-T Manager SecurityGlobalConfig Settings & Disable CRL Checking
If($DisableCRLChecking -eq $true){
Write-Host "Checking the Cluster 'CRL Checking' Status`n"
$NSXTMgrSCG = Invoke-Restmethod -Method GET -Uri "https://$Server/api/v1/global-configs/SecurityGlobalConfig" -Headers @{ Authorization = "Basic $($Credential)" }
    Switch ($NSXTMgrSCG.result)
        {
            Failure { 
                Write-Host "`n`tError: $($NSTXMgrSCG.error)`n" -ForegroundColor Red
                Exit
            }
        }
                If($NSXTMgrSCG.crl_checking_enabled -eq $false){
                   Write-Host "`t'CRL Checking' is already disabled`n" -ForegroundColor Green
                }
                Else {
                   Write-Host "`t'CRL Checking' is enabled, proceeding to disabled it" -ForegroundColor Yellow
                   #Disable CRL Checking in SecurityGlobalConfig
                   $NSXTMgrSCGUpdateBody = "{`"crl_checking_enabled`":false,`"resource_type`":`"SecurityGlobalConfig`",`"_revision`":$($NSXTMgrSCG._revision)}"
                   $NSXTMgrSCGUpdate = Invoke-Restmethod -Method PUT -Uri "https://$Server/api/v1/global-configs/SecurityGlobalConfig" -Headers @{ Authorization = "Basic $($Credential)" } -Body $($NSXTMgrSCGUpdateBody) -ContentType 'application/json'
                        Switch ($NSXTMgrSCGUpdate.result)
                            {
                                Failure { 
                                    Write-Host "`n`t`tError: $($NSXTMgrSCGUpdate.error)`n"
                                    Exit
                                }
                            }
                                    If($NSXTMgrSCGUpdate.crl_checking_enabled -eq $false){
                                       Write-Host "`t`t'CRL Checking' has now been disabled`n" -ForegroundColor Green
                                    }
                                    Else {
                                       Write-Host "`t`tThere was a problem and 'CRL Checking' could NOT be disabled`n" -ForegroundColor Red
                                       Exit
                                    }
                }
}

#Get the NSX-T Manager SecurityGlobalConfig Settings & Enable CRL Checking
If($DisableCRLChecking -eq $false){
Write-Host "Checking the Cluster 'CRL Checking' Status`n"
$NSXTMgrSCG = Invoke-Restmethod -Method GET -Uri "https://$Server/api/v1/global-configs/SecurityGlobalConfig" -Headers @{ Authorization = "Basic $($Credential)" }
    Switch ($NSXTMgrSCG.result)
        {
            Failure { 
                Write-Host "`n`tError: $($NSTXMgrSCG.error)`n" -ForegroundColor Red
                Exit
            }
        }
                If($NSXTMgrSCG.crl_checking_enabled -eq $true){
                   Write-Host "`t'CRL Checking' is already enabled`n" -ForegroundColor Green
                }
                Else {
                   Write-Host "`t'CRL Checking' is disabled, proceeding to enable it" -ForegroundColor Yellow
                   #Disable CRL Checking in SecurityGlobalConfig
                   $NSXTMgrSCGUpdateBody = "{`"crl_checking_enabled`":true,`"resource_type`":`"SecurityGlobalConfig`",`"_revision`":$($NSXTMgrSCG._revision)}"
                   $NSXTMgrSCGUpdate = Invoke-Restmethod -Method PUT -Uri "https://$Server/api/v1/global-configs/SecurityGlobalConfig" -Headers @{ Authorization = "Basic $($Credential)" } -Body $($NSXTMgrSCGUpdateBody) -ContentType 'application/json'
                        Switch ($NSXTMgrSCGUpdate.result)
                            {
                                Failure { 
                                    Write-Host "`n`t`tError: $($NSXTMgrSCGUpdate.error)`n"
                                    Exit
                                }
                            }
                                    If($NSXTMgrSCGUpdate.crl_checking_enabled -eq $true){
                                       Write-Host "`t`t'CRL Checking' has now been enabled`n" -ForegroundColor Green
                                    }
                                    Else {
                                       Write-Host "`t`tThere was a problem and 'CRL Checking' could NOT be enabled`n" -ForegroundColor Red
                                       Exit
                                    }
                }
}

#Get the Certificates from NSX-T & present in Grid for selection
Write-Host "Select the Certificate to be used on all Nodes and the Cluster`n"
$NSXTMgrAllCerts = Invoke-Restmethod -Method GET -Uri "https://$Server/api/v1/trust-management/certificates" -Headers @{ Authorization = "Basic $($Credential)" } | Select-Object -ExpandProperty results
$NSXTMgrAllCertsResult = $NSXTMgrAllCerts | Select-Object @{N="Certificate Name"; E={$($_.display_name)}},@{N="Certificate ID"; E={$($_.id)}},@{N="Created By"; E={$($_._create_user)}} | Sort-Object "Certificate Name" | Out-GridView -Title  "Which certificate do you wish to apply?" -OutputMode Single 
    If(!$NSXTMgrAllCertsResult){
       Write-Host "`tNo Certificate was selected. Cannot continue!`n" -ForegroundColor Red
       Exit
       }
Write-Host "`tCertificate Details`n"
Write-Host "`t`tName: $($NSXTMgrAllCertsResult.'Certificate Name')" -ForegroundColor Yellow
Write-Host "`t`tID: $($NSXTMgrAllCertsResult.'Certificate ID')" -ForegroundColor Yellow
Write-Host "`t`tCreated By: $($NSXTMgrAllCertsResult.'Created By')`n" -ForegroundColor Yellow

#Update all Node Certificates
Write-Host "Changing the Certificate on all Nodes`n"
ForEach ($NSXTMgr in $NSXTCluster) {
    #Update the Certificate that Tomcat is using for this node
    Write-Host "`tChanging the Certificate for Node $($NSXTMgr.FQDN) to Certificate ID $($NSXTMgrAllCertsResult.'Certificate ID')`n" -ForegroundColor Yellow
    Try {
        $NSXTMgrSCGNewCert = Invoke-Restmethod -Method POST -Uri "https://$($NSXTMgr.FQDN)/api/v1/node/services/http?action=apply_certificate&certificate_id=$($NSXTMgrAllCertsResult.'Certificate ID')" -Headers @{ Authorization = "Basic $($Credential)" } -ErrorAction SilentlyContinue -ErrorVariable IRErr
    } Catch {
        Write-Host "`tUnable to update the Node Certificate" -ForegroundColor Red
        $IRErrObj = $IRErr.message | ConvertFrom-Json
        Write-Host "`t`tError: $($IRErrObj.error_code)" -ForegroundColor Red
        Write-Host "`t`tError: $($IRErrObj.error_message)`n" -ForegroundColor Red
        Exit
    }
        Write-Host "`t`tNode Certificate has been updated`n" -ForegroundColor Green
}


#Update the Cluster Certificate
Write-Host "Changing Certificate on the Cluster`n"
    Try {
        $NSXMgrClusterNewCert = Invoke-Restmethod -Method POST -Uri "https://$Server/api/v1/cluster/api-certificate?action=set_cluster_certificate&certificate_id=$($NSXTMgrAllCertsResult.'Certificate ID')" -Headers @{ Authorization = "Basic $($Credential)" } -ErrorAction SilentlyContinue -ErrorVariable IRErr
    } Catch {
        Write-Host "`tUnable to update the Cluster Certificate" -ForegroundColor Red
        $IRErrObj = $IRErr.message | ConvertFrom-Json
        Write-Host "`tError Code: $($IRErrObj.error_code)" -ForegroundColor Red
        Write-Host "`tError Message: $($IRErrObj.error_message)`n" -ForegroundColor Red
        Exit
    }
        Write-Host "`tCluster Certificate has been updated`n" -ForegroundColor Green

#Done. Clear Variabled and Exit
Write-Host "Done!"
Remove-Variable -Name * -ErrorAction SilentlyContinue
$Global:ProgressPreference = "Continue"
Exit