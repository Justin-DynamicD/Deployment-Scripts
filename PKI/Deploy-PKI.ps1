﻿param (
    [Parameter(Mandatory=$true)][String][ValidateSet("Root","Issue")]$Role,
    [Parameter(Mandatory=$true)][String]$FQDN = "pki.contoso.com",
    [Parameter(Mandatory=$true)][String]$CAName,
    [Parameter(Mandatory=$false)][String]$DomainDN,
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
    #Install and configure core features
    Write-Verbose "Installing required features..."
    Switch ($Role) {
        Issue {
            Add-WindowsFeature ADCS-Cert-Authority,ADCS-Web-Enrollment -IncludeManagementTools
            Install-ADcsCertificationAuthority -CACommonName $CAName -CAType EnterpriseSubordinateCA -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -Force
            }
        Root {
            Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
            Install-ADcsCertificationAuthority -CACommonName $CAName -CAType StandaloneRootCA -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 20 -Force
            }
        } #end switch
    } # End "IssueStep 1" Condition

#Configure the Root Server
If ($Role -eq "Root") {
    
    #Set the registry information on the certificate service
    Write-Verbose "Setting the registry information..."
    $cmd = 'certutil.exe -setreg ca\DSConfigDN "CN=Configuration,'+$DomainDN+'"'
    Invoke-Expression $cmd | Write-Verbose

    #Configure the CRL, CDP and CA Publication URLs
    Write-Verbose "Setting publication URLs..."
    $cmd = 'certutil.exe -setreg CA\CRLPublicationURLs "1:'+$env:SystemRoot+'\system32\CertSrv\CertEnroll\%3%8%9.crl\n2:http://'+$FQDN+'/pki/%3%8%9.crl"'
    Invoke-Expression $cmd | Write-Verbose
    $cmd = 'certutil.exe -setreg CA\CACertPublicationURLs "1:'+$env:SystemRoot+'\system32\CertSrv\CertEnroll\%1_%3%4.crt\n2:http://'+$FQDN+'/pki/%1_%3%4.crt"'
    Invoke-Expression $cmd | Write-Verbose

    #Configure the CRL Validity Period
    Write-Verbose "Configure the CRL Validity Period..."

    #Enable Auditing
    Write-Verbose "Enable Auditing ..."
    $cmd = 'certutil.exe -setreg ca\AuditFilter 127'

    #Resart Services to apply
    write-verbose "Restarting services to apply changes ..."
    restart-service certsvc

    #Exporting Information
    Write-Verbose "Exporting Information..."
    $cmd = 'certutil.exe -CRL'

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
    $CRLs = (Get-ChildItem -Path $Destination\* -Include *.crl).Name
    For-each $Certfile in $certs {
        $cmd = 'certutil.exe -dspublish -f "'+$Destination+'\'+$certfile+'" RootCA'
        $cmd = 'certutil.exe -addstore -f root "'+$Destination+'\'+$certfile+'"'
        }
     For-each $CRLfile in $CRLs {
        $cmd = 'certutil.exe -addstore -f root "'+$Destination+'\'+$CRLfile+'"'
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

    #Configure the CRL, CDP and CA Publication URLs
    Write-Verbose "Setting publication URLs..."
    $cmd = 'certutil.exe -setreg CA\CRLPublicationURLs "1:'+$env:SystemRoot+'\system32\CertSrv\CertEnroll\%3%8%9.crl\n2:http://'+$FQDN+'/pki/%3%8%9.crl\n1:file://'+$env:SystemDrive+'\pki\%3%8%9.crl"'
    Invoke-Expression $cmd | Write-Verbose
    $cmd = 'certutil.exe -setreg CA\CACertPublicationURLs "1:'+$env:SystemRoot+'\system32\CertSrv\CertEnroll\%1_%3%4.crt\n2:http://'+$FQDN+'/pki/%1_%3%4.crt\n1:file://'+$env:SystemDrive+'\pki\%3%8%9.crl"'
    Invoke-Expression $cmd | Write-Verbose

    #Configure the CRL Validity Period
    Write-Verbose "Configure the CRL Validity Period..."

    #Enable Auditing
    Write-Verbose "Enable Auditing ..."
    $cmd = 'certutil.exe -setreg ca\AuditFilter 127'

    #Resart Services to apply
    write-verbose "Restarting services to apply changes ..."
    restart-service certsvc

    #Exporting Information
    Write-Verbose "Exporting Information..."
    $cmd = 'certutil.exe -CRL'

    }