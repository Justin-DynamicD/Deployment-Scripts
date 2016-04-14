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

#This Function is used to copy files over Winrm as WMF4 doesn't have a native cmdlet; see notes for credit
function Send-File
{
	<#
	.SYNOPSIS
		This function sends a file (or folder of files recursively) to a destination WinRm session. This function was originally
		built by Lee Holmes (http://poshcode.org/2216) but has been modified to recursively send folders of files as well
		as to support UNC paths.

	.PARAMETER Path
		The local or UNC folder path that you'd like to copy to the session. This also support multiple paths in a comma-delimited format.
		If this is a UNC path, it will be copied locally to accomodate copying.  If it's a folder, it will recursively copy
		all files and folders to the destination.

	.PARAMETER Destination
		The local path on the remote computer where you'd like to copy the folder or file.  If the folder does not exist on the remote
		computer it will be created.

	.PARAMETER Session
		The remote session. Create with New-PSSession.

	.EXAMPLE
		$session = New-PSSession -ComputerName MYSERVER
		Send-File -Path C:\test.txt -Destination C:\ -Session $session

		This example will copy the file C:\test.txt to be C:\test.txt on the computer MYSERVER

	.INPUTS
		None. This function does not accept pipeline input.

	.OUTPUTS
		System.IO.FileInfo
	#>
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string[]]$Path,
		
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$Destination,
		
		[Parameter(Mandatory)]
		[System.Management.Automation.Runspaces.PSSession]$Session
	)
	process
	{
		foreach ($p in $Path)
		{
			try
			{
				if ($p.StartsWith('\\'))
				{
					Write-Verbose -Message "[$($p)] is a UNC path. Copying locally first"
					Copy-Item -Path $p -Destination ([environment]::GetEnvironmentVariable('TEMP', 'Machine'))
					$p = "$([environment]::GetEnvironmentVariable('TEMP', 'Machine'))\$($p | Split-Path -Leaf)"
				}
				if (Test-Path -Path $p -PathType Container)
				{
					Write-Log -Source $MyInvocation.MyCommand -Message "[$($p)] is a folder. Sending all files"
					$files = Get-ChildItem -Path $p -File -Recurse
					$sendFileParamColl = @()
					foreach ($file in $Files)
					{
						$sendParams = @{
							'Session' = $Session
							'Path' = $file.FullName
						}
						if ($file.DirectoryName -ne $p) ## It's a subdirectory
						{
							$subdirpath = $file.DirectoryName.Replace("$p\", '')
							$sendParams.Destination = "$Destination\$subDirPath"
						}
						else
						{
							$sendParams.Destination = $Destination
						}
						$sendFileParamColl += $sendParams
					}
					foreach ($paramBlock in $sendFileParamColl)
					{
						Send-File @paramBlock
					}
				}
				else
				{
					Write-Verbose -Message "Starting WinRM copy of [$($p)] to [$($Destination)]"
					# Get the source file, and then get its contents
					$sourceBytes = [System.IO.File]::ReadAllBytes($p);
					$streamChunks = @();
					
					# Now break it into chunks to stream.
					$streamSize = 1MB;
					for ($position = 0; $position -lt $sourceBytes.Length; $position += $streamSize)
					{
						$remaining = $sourceBytes.Length - $position
						$remaining = [Math]::Min($remaining, $streamSize)
						
						$nextChunk = New-Object byte[] $remaining
						[Array]::Copy($sourcebytes, $position, $nextChunk, 0, $remaining)
						$streamChunks +=, $nextChunk
					}
					$remoteScript = {
						if (-not (Test-Path -Path $using:Destination -PathType Container))
						{
							$null = New-Item -Path $using:Destination -Type Directory -Force
						}
						$fileDest = "$using:Destination\$($using:p | Split-Path -Leaf)"
						## Create a new array to hold the file content
						$destBytes = New-Object byte[] $using:length
						$position = 0
						
						## Go through the input, and fill in the new array of file content
						foreach ($chunk in $input)
						{
							[GC]::Collect()
							[Array]::Copy($chunk, 0, $destBytes, $position, $chunk.Length)
							$position += $chunk.Length
						}
						
						[IO.File]::WriteAllBytes($fileDest, $destBytes)
						
						Get-Item $fileDest
						[GC]::Collect()
					}
					
					# Stream the chunks into the remote script.
					$Length = $sourceBytes.Length
					$streamChunks | Invoke-Command -Session $Session -ScriptBlock $remoteScript
					Write-Verbose -Message "WinRM copy of [$($p)] to [$($Destination)] complete"
				}
			}
			catch
			{
				Write-Error $_.Exception.Message
			}
		}
	}
	
}#End Function Send-File

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

Write-Verbose "Importing ServerManager if it's not loaded ..."
If (!(Get-Module ServerManager)){
    Import-Module ServerManager
    }

#Test Connectivity to Root Server
try {
    #invoke a command to get WinRM service status
    $RootSession = New-PSSession -ComputerName $RootServer -Credential $RootCredentials -ErrorAction Stop
    Invoke-Command -Session $RootSession -ScriptBlock {Get-Service | Where-Object {($_.Name -eq "WinRM") -and ($_.Status -eq "Running")}} -ErrorAction Stop | Write-Verbose
        
    #success output 
    Write-Verbose "WinRM connection to the Offline Root Suceeded" 
    }
catch{
    #Failure output
    Write-Error "WinRM is not running or cannnot be validated on $RootServer, please verify connectivity and credentials" -ErrorAction Stop
    } 

#Copy and update the Policy Files to the Appropriate location
Write-Verbose "Creating capolicy.inf files ..."
try {
    (Get-Content "Root-CAPolicy.inf").replace('[FQDN]',$FQDN) | Set-Content $env:SystemRoot\CAPolicy.inf -force -ErrorAction Stop
    Send-File -Path $env:SystemRoot\CAPolicy.inf -Destination $env:SystemRoot -Session $RootSession -ErrorAction Stop
    (Get-Content "Issue-CAPolicy.inf").replace('[FQDN]',$FQDN) | Set-Content $env:SystemRoot\CAPolicy.inf -force -ErrorAction Stop
    }
catch {
    Write-Error -Message "Unable to create CAPolicy.inf in the correct location.  Please verify permissions." -ErrorAction Stop
    }

#Build Root Server
Write-Verbose "Begin installing the Root Server"

####  Below this point is legacy code ####

#Only process installs if we are on step 1
If ($IssueStep -eq 1) {

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
