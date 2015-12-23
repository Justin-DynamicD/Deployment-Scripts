######################################################################################
# The Get-TargetResource cmdlet.
# This function will get the present SQL instances on the system
######################################################################################
function Get-TargetResource
{
[CmdletBinding()][OutputType([System.Collections.Hashtable])]
param (
    [Parameter(Mandatory=$false)][String]$WinSources,
    [Parameter(Mandatory=$false)][String]$ISOImage,
    [Parameter(Mandatory=$false)][String]$ConfigurationFile
    )
 
    $sqlInstances = gwmi win32_service -computerName localhost | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } | % { $_.Caption }
    $res = $sqlInstances -ne $null -and $sqlInstances -gt 0
    $vals = @{
        Installed = $res;
        InstanceCount = $sqlInstances.count
        }
    $vals
 } #End Function


######################################################################################
# The Test-TargetResource cmdlet.
# This replies a $true or $false for each setting
######################################################################################
function Test-TargetResource
{
[CmdletBinding()][OutputType([System.Boolean])]
param (
    [Parameter(Mandatory=$false)][String]$WinSources,
    [Parameter(Mandatory=$false)][String]$ISOImage,
    [Parameter(Mandatory=$false)][String]$ConfigurationFile
    )

ValidateProperties @PSBoundParameters

   } #End Function


######################################################################################
# The Set-TargetResource cmdlet.
# This Applies all variables to the install script by adding "-apply"
######################################################################################
function Set-TargetResource
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][String]$WinSources = "\\FS-01\Deployment\Server_2012R2\Sources\SXS",
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][String]$ISOImage = "\\FS-01\Deployment\SQL_2014\sql_server_2014_standard.iso",
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][String]$ConfigurationFile = "\\FS-01\Deployment\SQL_2014\SQL-Configuration.ini",
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][String]$SQLSVCPASSWORD,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][String]$AGTSVCPASSWORD
        )

    ValidateProperties @PSBoundParameters -Apply

   } #End Function


#######################################################################################
#  Helper function that validates the SQL Install. If the switch parameter
# "Apply" is set, then it will set the properties after a test
#######################################################################################
function ValidateProperties
{
    param (
        [Parameter(Mandatory=$false)][String]$WinSources,
        [Parameter(Mandatory=$false)][String]$ISOImage,
        [Parameter(Mandatory=$false)][String]$ConfigurationFile,
        [Parameter(Mandatory=$false)][String]$SQLSVCPASSWORD,
        [Parameter(Mandatory=$false)][String]$AGTSVCPASSWORD,
        [Parameter(Mandatory=$false)][Switch]$Apply
        )

    #Start assuming the configuration will be valid.
    [boolean]$ConfigurationValid = $true

    #Set staging directory for disk with the most free space
    $StagingPath = (get-volume |sort-object SizeRemaining -Descending)[0].Driveletter + ':\temp'

    #Test if all .Net requirements are met
    If (((Get-WindowsFeature Net-Framework-Core).InstallState) -ne "Installed") {
        Write-Verbose ".Net 3.5 Is not Installed"
        If($Apply){
            Install-WindowsFeature Net-Framework-Core -Source $winsources
            }
        Else {$ConfigurationValid = $false}
        } #End 3.5 Check
    If (((Get-WindowsFeature Net-Framework-Core).InstallState) -ne "Installed") {
        Write-Verbose ".Net 4.5 Is not Installed"
        If($Apply){
            Install-WindowsFeature Net-Framework-45-Core
            }
        Else {$ConfigurationValid = $false}
        } #End 45 Check

    #If Apply is set, stage ISO and unattend files to local path
    If ($Apply) {
        if (!(test-path $StagingPath)) {new-item -ItemType Directory $StagingPath | Out-Null}
        if (!(test-path $StagingPath\SQLServer.iso)) {copy-item $ISOImage $StagingPath\SQLServer.iso -Force | Out-Null}
        if (!(test-path $StagingPath\ConfigurationFile.ini)) {copy-item $ConfigurationFile $StagingPath\ConfigurationFile.ini -Force | Out-Null}
        }

    #Check for SQL Installation
    $sqlInstances = gwmi win32_service -computerName localhost | ? { $_.Name -match "mssql*" -and $_.PathName -match "sqlservr.exe" } | % { $_.Caption }
    $res = $sqlInstances -ne $null -and $sqlInstances -gt 0

    #Take Action based on $RES being present
    if ($res) {
        Write-Verbose "SQL Server is already installed"
        }
    else {
        if ($apply) {
            Write-Verbose "Installing SQL..."
            # mount the iso
            $setupDriveLetter = (Mount-DiskImage -ImagePath $StagingPath\SQLServer.iso -PassThru | Get-Volume).DriveLetter
            if ($setupDriveLetter -eq $null) {
                throw "Could not mount SQL install iso"
                }
            Write-Verbose "Drive letter for iso is: $setupDriveLetter"
                 
            # run the installer using the ini file
            $cmd = $setupDriveLetter + ':\Setup.exe /ConfigurationFile='+$StagingPath+'\ConfigurationFile.ini /SQLSVCPASSWORD="'+$SQLSVCPASSWORD+'" /AGTSVCPASSWORD="'+$AGTSVCPASSWORD+'" /IAcceptSQLServerLicenseTerms'
            Write-Verbose "Running SQL Install - check %programfiles%\Microsoft SQL Server\120\Setup Bootstrap\Log\ for logs..."
            Invoke-Expression $cmd | Write-Verbose

            #unmount the ISO when complete
            Dismount-DiskImage -ImagePath $StagingPath\SQLServer.iso -PassThru

            } #End SQL Install
        else { $ConfigurationValid = $false}
        } #End Nest If Function for install vs report

    #if apply got this far without errors, remove the staged files
    If (($Apply) -and ($ConfigurationValid)) {
        if (test-path $StagingPath\SQLServer.iso) {remove-item $StagingPath\SQLServer.iso -Force | Out-Null}
        if (test-path $StagingPath\ConfigurationFile.ini) {remove-item $StagingPath\ConfigurationFile.ini -Force | Out-Null}
        }

    #if this is a test only, report back compliance boolean
    If (!($Apply)) {
        return $ConfigurationValid
        }
   } #End Function
