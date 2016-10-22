#Requires -Version 5
#Requires -RunasAdministrator

<#
.SYNOPSIS
   Deploys a two-tier PKI hierarchy with offline root
.DESCRIPTION
   This script will install and configure a two-tier PKI hierarchy complete with offline root.  Because of the nature of an offlineroot, the script will be run seperately on each node.
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

param (
    [Parameter(Mandatory=$true)]
    [String]$FQDN,
    
    [Parameter(Mandatory=$true)]
    [String]$CAName,
    
    [Parameter(Mandatory=$true)]
    [pscredential]$RootCredentials,
    
    [Parameter(Mandatory=$true)]
    [String]$RootServer,
    
    [Parameter(Mandatory=$true)]
    [String]$RootName,
    
    [Parameter(Mandatory=$false)]
    [Switch]$CreateDeploymentZIP = $false,
    
    [Parameter(Mandatory=$false)]
    [Switch]$DeployZIPAD = $false
    )

Write-Output "Importing ServerManager if it's not loaded ..."
If (!(Get-Module ServerManager)){
    Import-Module ServerManager
    }

#Test Connectivity to Root Server and check if RootCA is already defined by looking for the CAPolicy.inf file
try {
    #invoke a command to get WinRM service status
    $RootSession = New-PSSession -ComputerName $RootServer -Credential $RootCredentials -ErrorAction Stop
    $RootConfigured = (Invoke-Command -Session $RootSession -ScriptBlock {Test-Path $env:SystemRoot\CAPolicy.inf})
    
    #success output 
    Write-Verbose "WinRM connection to the Offline Root Suceeded" 
    }
catch{
    #Failure output
    Write-Error "WinRM is not running or cannnot be validated on $RootServer, please verify connectivity and credentials" -ErrorAction "Stop"
    } 

#If switch $DeployZIPAD is set and we are in workgroup mode, Stop
If ($DeployZIPAD -and ($env:Userdomain -eq $env:COMPUTERNAME)) {
    Write-Error "cannot publish to AD from a workgroup computer, but publish was specified" -ErrorAction "Stop"
    }

#Copy and update the Policy Files to the Appropriate location
Write-Output "Creating capolicy.inf files ..."
try {
    If (!$RootConfigured) {
        (Get-Content "Root-CAPolicy.inf").replace('[FQDN]',$FQDN) | Set-Content $env:SystemRoot\CAPolicy.inf -force -ErrorAction "Stop"
        Copy-Item -Path $env:SystemRoot\CAPolicy.inf -Destination $env:SystemRoot -ToSession $RootSession -ErrorAction "Stop"
        }
    (Get-Content "Issue-CAPolicy.inf").replace('[FQDN]',$FQDN) | Set-Content $env:SystemRoot\CAPolicy.inf -force -ErrorAction "Stop"
    }
catch {
    Write-Error -Message "Unable to create CAPolicy.inf in the correct location.  Please verify permissions." -ErrorAction "Stop"
    }

#Install Missing Roles and Features
Write-Output "Installing required features..."
#Local CA
Add-WindowsFeature ADCS-Cert-Authority,ADCS-Web-Enrollment -IncludeManagementTools
Install-ADcsCertificationAuthority -CACommonName $CAName -CAType EnterpriseSubordinateCA -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -Force
#Root CA
Invoke-Command -Session $RootSession -ScriptBlock {
        Add-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
        Install-ADcsCertificationAuthority -CACommonName $CAName -CAType StandaloneRootCA -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 20 -Force
        }

#Configure the Root Server
Write-Verbose "Configuring the Root Server if needed"
If (!$RootConfigured) {
    Invoke-Command -Session $RootSession -ScriptBlock {
        
        #Configure the CRL, CDP and CA Publication URLs
        Write-Verbose "Setting publication URLs..."
        certutil.exe -setreg CA\CRLPublicationURLs "1:$env:SystemRoot\system32\CertSrv\CertEnroll\%3%8%9.crl\n2:http://$FQDN/pki/%3%8%9.crl" | Write-Verbose
        certutil.exe -setreg CA\CACertPublicationURLs "1:$env:SystemRoot\system32\CertSrv\CertEnroll\%1_%3%4.crt\n2:http://$FQDN/pki/%1_%3%4.crt" | Write-Verbose

        #Configure the CRL Validity Period
        Write-Verbose "Configure the CRL Validity Period..."
        certutil.exe -setreg ca\ValidityPeriodUnits 10 | Write-Verbose
        certutil.exe -setreg ca\ValidityPeriod "Years" | Write-Verbose

        #Enable Auditing
        Write-Verbose "Enable Auditing ..."
        certutil.exe -setreg ca\AuditFilter 127 | Write-Verbose

        #Resart Services to apply
        write-verbose "Restarting services to apply changes ..."
        restart-service certsvc
        
        #Exporting Information
        Write-Verbose "Exporting Information..."
        certutil.exe -CRL | Write-Verbose
        
        #Wait for CRL Generation to finish
        while (!(Test-Path "$env:SystemRoot\system32\CertSrv\CertEnroll\*" -Filter *.crl)) {Start-Sleep 2}
        }#End Script Block
    } # End ConfigureRoot

#Create a fresh copy of the zipFile
Write-Output "Creating a ZIP of certificate files on $RootServer..."
Invoke-Command -Session $RootSession -ScriptBlock {
    $source = $env:SystemRoot+'\system32\CertSrv\CertEnroll'
    $Destination = $env:SystemDrive+'\root-certificates.zip'
    If(Test-path $destination) {Remove-item $destination}
    Add-Type -assembly "system.io.compression.filesystem"
    [io.compression.zipfile]::CreateFromDirectory($Source, $destination) 
    }#End Script Block

#Copy Certificates to local CA
$Source = $env:SystemDrive+'\root-certificates.zip'
Write-Output "Downloading CA and CRL from $RootServer"
Copy-Item -Path $source -Destination $env:SystemDrive -FromSession $RootSession -Force -ErrorAction "Stop"

#Extract Conents into a temp folder for processing
Write-Output "Extracting Contents ..."
$Destination = $env:SystemDrive+'\temp\certs'
If(Test-path $destination) {Remove-item $destination -recurse}
Add-Type -assembly "system.io.compression.filesystem"
[io.compression.zipfile]::ExtractToDirectory($Source, $destination)

#Push all certificates in the zip to the requested location
$certs = (Get-ChildItem -Path $Destination\* -Include *.crt).Name
Foreach ($Certfile in $certs) {
    If ($DeployZIPAD) {
        Write-Output "adding $certfile to AD..."
        certutil.exe -dspublish -f $Destination\$certfile RootCA | Write-Verbose
        }#End DeployZipAD
    
    #X509Certificate2 object that will represent the certificate, then import
    $CertPrint = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $certPrint.Import($Destination+'\'+$Certfile)

    #Check to see if Certificate already exists, add if not
    $match = get-childitem Cert:\LocalMachine\Root | where-object {$_.Thumbprint -eq $CertPrint.Thumbprint}
    If (!$match) {
        Write-Output "cannot find $($CertPrint.Thumbprint) in the store, adding..."
        certutil.exe -addstore -f root $Destination\$certfile | Write-Verbose
        }
    }

#cleanup temp directory
If(Test-path $destination) {Remove-item $destination -recurse}

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





If (($Role -eq "Issue") -and ($IssueStep -eq 2)) {
    


    
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
