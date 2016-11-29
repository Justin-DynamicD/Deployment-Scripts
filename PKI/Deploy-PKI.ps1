<#
.Synopsis
   Deploys a two-tier PKI hierarchy with offline root
.DESCRIPTION
   This script will install and configure a two-tier PKI hierarchy complete with offline root.  Becuase of the nature of an offlineroot, the script will be run seperately on each node.
.EXAMPLE
   Deploy-pki.ps1 –role root –FQDN “pki.contoso.com” –CAName “Contoso Inc.”

   Run this on the box you want to be your “root server”.  It should not be domain joined so it can remain off forever and a day.  When done, it will create a zip file on your C: drive it will use for later portions called “root-certificates.zip”.  Copy that to your Enterprise CA in the root of C: again.
.EXAMPLE
   Deploy-pki.ps1 –role issue –FQDN “pki.contoso.com” –CAName “Contoso Inc. Enterprise CA” -DeployZIPAD

   Similar commands as the first, only this time say “issue” and we add “-deployzipad” to tell the script to look for that file created earlier and publish the root certificates to AD.  Remove that last switch if you need to re-run the server build for any reason.

   When done … you will have a certificate request file in your C:\ drive this time.  You’ve got to take that to your root server and issue a cert based on the request.  One you have a cert, you can import the cert into the server using cert authority GUI.  Hurray.
.EXAMPLE
   Deploy-pki.ps1 –role issue –FQDN “pki.contoso.com” –CAName “Contoso Inc. Enterprise CA” –DeployZIP –IssueStep 2

   Two new switches here.  “–IssueStep 2” tells the script that the cert was installed and it’s safe to finish configuring settings.  “–DeployZip” tells it to take those certs on the root and host them on the local IIS (so you can shut down the root server).  Once this finishes your PKI structure is up … just make sure you add a A-Record for that “pki.contoso.com” so it can be resolved.  You can also now delete those request files and zip files on your C:\
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   root-certificates.zip - this file contains the public key and current CRL file to be imported into AD with the DeployZipAD switch.
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>

#Requires -RunasAdministrator

param (
    [Parameter(Mandatory=$true)][String][ValidateSet("Root","Issue")]$Role,
    [Parameter(Mandatory=$true)][String]$FQDN = "pki.contoso.com",
    [Parameter(Mandatory=$true)][String]$CAName,
    [Parameter(Mandatory=$false)][Int][ValidateSet(1,2)]$IssueStep = 1,
    [Parameter(Mandatory=$false)][Switch]$CreateDeploymentZIP = $true,
    [Parameter(Mandatory=$false)][Switch]$DeployZIP = $false,
    [Parameter(Mandatory=$false)][Switch]$DeployZIPAD = $false
    )

Write-Verbose "Importing ServerManager is it's not loaded ..."
If (!(Get-Module ServerManager)){
    Import-Module ServerManager
    }

#Only process installs if we are on step 1
If ($IssueStep -eq 1) {

    #Select Template Based on $Role
    Switch ($Role) {
        Issue {$catemplate="Issue-CAPolicy.inf"}
        Root {$catemplate="Root-CAPolicy.inf"}
        }

    #Generate CAPolicy.inf from templates
    Write-Verbose "Creating capolicy.inf file ..."
    (Get-Content $catemplate).replace('[FQDN]',$FQDN) | Set-Content $env:SystemRoot\CAPolicy.inf -force


    #Install and configure core features
    Write-Verbose "Installing required features..."
    Switch ($Role) {
        Issue {
            Add-WindowsFeature ADCS-Cert-Authority,ADCS-Web-Enrollment -IncludeManagementTools
            $Params = @{
                CACommonName = $CAName
                CAType = "EnterpriseSubordinateCA"
                CryptoProviderName = "RSA#Microsoft Software Key Storage Provider"
                }
            Install-ADcsCertificationAuthority @Params -Force
            }
        Root {
            Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
            $Params = @{
                CACommonName = $CAName
                CAType = "StandaloneRootCA"
                CryptoProviderName = "RSA#Microsoft Software Key Storage Provider"
                KeyLength = 4096
                HashAlgorithmName = "SHA256"
                ValidityPeriod = "Years"
                ValidityPeriodUnits = 20
                }
            Install-ADcsCertificationAuthority @Params -Force
            }
        } #end switch
    } # End "IssueStep 1" Condition

#Configure the Root Server
If ($Role -eq "Root") {
    
    #Configure the CRL, CDP and CA Publication URLs
    Write-Verbose "Setting publication URLs..."
    $cmd = 'certutil.exe -setreg CA\CRLPublicationURLs "1:'+$env:SystemRoot+'\system32\CertSrv\CertEnroll\%3%8%9.crl\n2:http://'+$FQDN+'/pki/%3%8%9.crl"'
    Invoke-Expression $cmd | Write-Verbose
    $cmd = 'certutil.exe -setreg CA\CACertPublicationURLs "1:'+$env:SystemRoot+'\system32\CertSrv\CertEnroll\%1_%3%4.crt\n2:http://'+$FQDN+'/pki/%1_%3%4.crt"'
    Invoke-Expression $cmd | Write-Verbose

    #Configure the CRL Validity Period
    Write-Verbose "Configure the CRL Validity Period..."
    $cmd = 'certutil.exe -setreg ca\ValidityPeriodUnits 10'
    Invoke-Expression $cmd | Write-Verbose
    $cmd = 'certutil.exe -setreg ca\ValidityPeriod "Years"'
    Invoke-Expression $cmd | Write-Verbose

    #Enable Auditing
    Write-Verbose "Enable Auditing ..."
    $cmd = 'certutil.exe -setreg ca\AuditFilter 127'
    Invoke-Expression $cmd | Write-Verbose

    #Resart Services to apply
    write-verbose "Restarting services to apply changes ..."
    restart-service certsvc

    #Exporting Information
    Write-Verbose "Exporting Information..."
    $cmd = 'certutil.exe -CRL'
    Invoke-Expression $cmd | Write-Verbose
    
    #Wait for CRL Generation to finish
    while (!(Test-Path "$env:SystemRoot\system32\CertSrv\CertEnroll\*" -Filter *.crl)) {Start-Sleep 2}

    #Create a ZIP of certificate files if switch is set
    IF ($CreateDeploymentZIP) {
        Write-Verbose "Creating a ZIP of certificate files..."
        $source = $env:SystemRoot+'\system32\CertSrv\CertEnroll'
        $Destination = $env:SystemDrive+'\root-certificates.zip'
        If(Test-path $destination) {Remove-item $destination}
        Add-Type -assembly "system.io.compression.filesystem"
        [io.compression.zipfile]::CreateFromDirectory($Source, $destination) 
        } # End Zip variable
    } # End Root

#If switch $DeployZIPAD is set and we are not in workgroup mode, push all certificates in the zip to AD
If (($DeployZIPAD) -and ($env:Userdomain -eq $env:COMPUTERNAME)) {Write-Error "cannot publish to AD from a workgroup computer"}
If (($DeployZIPAD) -and ($env:Userdomain -ne $env:COMPUTERNAME)) {
    
    #Unzip all the certificates to a temp directory
    $Source = $env:SystemDrive+'\root-certificates.zip'
    $Destination = $env:SystemDrive+'\temp\certs'
    If(Test-path $destination) {Remove-item $destination -recurse}
    Add-Type -assembly "system.io.compression.filesystem"
    [io.compression.zipfile]::ExtractToDirectory($Source, $destination)

    #publish each Cert to AD
    $certs = (Get-ChildItem -Path $Destination\* -Include *.crt).Name
    Foreach ($Certfile in $certs) {
        $cmd = 'certutil.exe -dspublish -f "'+$Destination+'\'+$certfile+'" RootCA'
        Invoke-Expression $cmd | Write-Verbose
        $cmd = 'certutil.exe -addstore -f root "'+$Destination+'\'+$certfile+'"'
        Invoke-Expression $cmd | Write-Verbose
        }
 
    #cleanup temp directory
    If(Test-path $destination) {Remove-item $destination -recurse}

    } #end AD Deployment

#Configure the Issueing Server on Step 2
If (($Role -eq "Issue") -and ($IssueStep -eq 2)) {
    
    #Configure the WebEnrollment service
    Install-AdcsWebEnrollment -Force

    #If DeployZip is set, unzip files to CertErnoll
    If ($DeployZIP) {
        $Source = $env:SystemDrive+'\root-certificates.zip'
        $Destination = $env:SystemRoot+'\System32\certsrv\CertEnroll'
        Add-Type -assembly "system.io.compression.filesystem"
        [io.compression.zipfile]::ExtractToDirectory($Source, $destination)
        }

    #Create PKI share directory and populate
    Write-Verbose "Creating new $env:SystemDrive\PKI ..."
    new-item -ItemType Directory $env:SystemDrive\PKI\Policy -force
    Copy-Item $env:SystemRoot\System32\certsrv\CertEnroll\* $env:SystemDrive\PKI -Force
    Write-Output "Legal Policy." | Out-File $env:SystemDrive\PKI\Policy\USLegalPolicy.asp
    Write-Output "Limited Use Policy." | Out-File $env:SystemDrive\PKI\Policy\USLimitedUsePolicy.asp

    #Update ACLs on PKI Folder
    $ACL = (Get-item $env:SystemDrive\PKI).GetAccessControl('Access')
    $AR = New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\IIS_IUSRS', 'ReadandExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $ACL.SetAccessRule($AR)
    Set-Acl -path $env:SystemDrive\PKI -AclObject $ACL

    #Create the Virtual Directory
    if (!(Get-WebVirtualDirectory pki)) {
        New-WebVirtualDirectory -Name pki -PhysicalPath $env:SystemDrive\PKI -Site "Default Web Site"
        }

    #Set Hash Algorithm to SHA256
    Write-Verbose "Set Hash Algorithm to SHA256..."
    $cmd = 'certutil.exe -setreg ca\csp\CNGHashAlgorithm SHA256'
    Invoke-Expression $cmd | Write-Verbose

    #Configure the CRL, CDP and CA Publication URLs
    Write-Verbose "Setting publication URLs..."
    $cmd = 'certutil.exe -setreg CA\CRLPublicationURLs "1:'+$env:SystemRoot+'\system32\CertSrv\CertEnroll\%3%8%9.crl\n2:http://'+$FQDN+'/pki/%3%8%9.crl\n1:file://'+$env:SystemDrive+'\pki\%3%8%9.crl"'
    Invoke-Expression $cmd | Write-Verbose
    $cmd = 'certutil.exe -setreg CA\CACertPublicationURLs "1:'+$env:SystemRoot+'\system32\CertSrv\CertEnroll\%1_%3%4.crt\n2:http://'+$FQDN+'/pki/%1_%3%4.crt\n1:file://'+$env:SystemDrive+'\pki\%3%8%9.crl"'
    Invoke-Expression $cmd | Write-Verbose

    #Configure the CRL Validity Period
    Write-Verbose "Configure the CRL Validity Period..."
    $cmd = 'certutil.exe -setreg ca\ValidityPeriodUnits 10'
    Invoke-Expression $cmd | Write-Verbose
    $cmd = 'certutil.exe -setreg ca\ValidityPeriod "Years"'
    Invoke-Expression $cmd | Write-Verbose

    #Enable Auditing
    Write-Verbose "Enable Auditing ..."
    $cmd = 'certutil.exe -setreg ca\AuditFilter 127'
    Invoke-Expression $cmd | Write-Verbose

    #Resart Services to apply
    write-verbose "Restarting services to apply changes ..."
    restart-service certsvc

    #Exporting Information
    Write-Verbose "Exporting Information..."
    $cmd = 'certutil.exe -CRL'
    Invoke-Expression $cmd | Write-Verbose

    }
