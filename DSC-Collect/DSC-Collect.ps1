param( [string]$DataPath, [switch]$AcceptEula )

$version = "DSC-Collect (20230419)"
# by Gianni Bragante - gbrag@microsoft.com

Function GetStore($store) {
  $certlist = Get-ChildItem ("Cert:\LocalMachine\" + $store)

  foreach ($cert in $certlist) {
    $EKU = ""
    foreach ($item in $cert.EnhancedKeyUsageList) {
      if ($item.FriendlyName) {
        $EKU += $item.FriendlyName + " / "
      } else {
        $EKU += $item.ObjectId + " / "
      }
    }

    $row = $tbcert.NewRow()

    foreach ($ext in $cert.Extensions) {
      if ($ext.oid.value -eq "2.5.29.14") {
        $row.SubjectKeyIdentifier = $ext.SubjectKeyIdentifier.ToLower()
      } elseif (($ext.oid.value -eq "2.5.29.35") -or ($ext.oid.value -eq "2.5.29.1")) { 
        $asn = New-Object Security.Cryptography.AsnEncodedData ($ext.oid,$ext.RawData)
        $aki = $asn.Format($true).ToString().Replace(" ","")
        $aki = (($aki -split '\n')[0]).Replace("KeyID=","").Trim()
        $row.AuthorityKeyIdentifier = $aki
      } elseif (($ext.oid.value -eq "1.3.6.1.4.1.311.21.7") -or ($ext.oid.value -eq "1.3.6.1.4.1.311.20.2")) { 
        $asn = New-Object Security.Cryptography.AsnEncodedData ($ext.oid,$ext.RawData)
        $tmpl = $asn.Format($true).ToString().Replace(" ","")
        $template = (($tmpl -split '\n')[0]).Replace("Template=","").Trim()
        $row.Template = $template
      }
    }
    if ($EKU) {$EKU = $eku.Substring(0, $eku.Length-3)} 
    $row.Store = $store
    $row.Thumbprint = $cert.Thumbprint.ToLower()
    $row.Subject = $cert.Subject
    $row.Issuer = $cert.Issuer
    $row.NotAfter = $cert.NotAfter
    $row.EnhancedKeyUsage = $EKU
    $row.SerialNumber = $cert.SerialNumber.ToLower()
    $tbcert.Rows.Add($row)
  } 
}

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

$global:Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path
$resName = "DSC-Results-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)

if ($DataPath) {
  if (-not (Test-Path $DataPath)) {
    Write-Host "The folder $DataPath does not exist"
    exit
  }
  $global:resDir = $DataPath + "\" + $resName
} else {
  $global:resDir = $global:Root + "\" + $resName
}
New-Item -itemtype directory -path $global:resDir | Out-Null

$global:outfile = $global:resDir + "\script-output.txt"
$global:errfile = $global:resDir + "\script-errors.txt"

Import-Module ($global:Root + "\Collect-Commons.psm1") -Force -DisableNameChecking

Write-Log $version
if ($AcceptEula) {
  Write-Log "AcceptEula switch specified, silently continuing"
  $eulaAccepted = ShowEULAIfNeeded "DSC-Collect" 2
} else {
  $eulaAccepted = ShowEULAIfNeeded "DSC-Collect" 0
  if($eulaAccepted -ne "Yes")
   {
     Write-Log "EULA declined, exiting"
     exit
   }
 }
Write-Log "EULA accepted, continuing"

Write-Log "PowerShell version"
$PSVersionTable | Out-File -FilePath ($global:resDir + "\PSVersion.txt") -Append

if (Test-Path -Path "C:\Program Files\WindowsPowerShell\DscService\RegistrationKeys.txt") {
  Write-Log "Registration keys"
  Copy-Item "C:\Program Files\WindowsPowerShell\DscService\RegistrationKeys.txt" ($global:resDir + "\RegistrationKeys.txt")
}

Write-Log "Collecing the dumps of the WMIPrvSE process having dsccore.dll or dsctimer.dll loaded"
try {
  $list = Get-Process -Name "WmiPrvSe" -ErrorAction SilentlyContinue 2>>$global:errfile
}
catch {
  Write-Log "Can't find any running WMIPrvSE process"
}
if (($list | measure).count -gt 0) {
  foreach ($proc in $list)
  {
    #$prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {($_.ModuleName -eq "dsccore.dll") -or ($_.ModuleName -eq "dsctimer.dll") } 
    if ((Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "dsccore.dll" } | Measure).Count -gt 0) {
      Write-Log ("Found " + $proc.Name + "(" + $proc.id + ")")
      CreateProcDump $proc.id $global:resDir "WMIPrvSE-DSCCore"
    }
    if ((Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "dsctimer.dll" } | Measure).Count -gt 0) {
      Write-Log ("Found " + $proc.Name + "(" + $proc.id + ")")
      CreateProcDump $proc.id $global:resDir "WMIPrvSE-DSCTimer"
    }
  }
}

$DSCDb = "C:\Program Files\WindowsPowerShell\DscService\Devices.edb"
if (Test-Path -Path ($env:windir + "\System32\inetsrv\Config\ApplicationHost.config")) {
  Write-Log "IIS ApplicationHost.config"
  Copy-Item "C:\Windows\System32\inetsrv\Config\ApplicationHost.config" ($global:resDir + "\ApplicationHost.config")

  $doc = (Get-content ($env:windir + "\System32\inetsrv\Config\ApplicationHost.config")) -as [xml]
  $logdir = ($doc.configuration.'system.applicationHost'.log.ChildNodes[1].directory).Replace("%SystemDrive%", $env:SystemDrive)
  
  foreach ($site in $doc.configuration.'system.applicationHost'.sites.site) {
    Write-Log ("Copying web.config and logs for the website " + $site.name)
    $sitedir = $global:resDir + "\websites\" + $site.name
    New-Item -itemtype directory -path $sitedir | Out-Null
    write-host $site.name, $site.application.ChildNodes[0].physicalpath
    $path = ($site.application.ChildNodes[0].physicalpath).Replace("%SystemDrive%", $env:SystemDrive)
    if (Test-Path -Path ($path + "\web.config")) {
      Copy-Item -path ($path + "\web.config") -destination $sitedir -ErrorAction Continue 2>>$global:errfile

      $siteLogDir = ($logdir + "\W3SVC" + $site.id)
      $last = Get-ChildItem -path ($siteLogDir) | Sort CreationTime -Descending | Select Name -First 1 
      Copy-Item ($siteLogDir + "\" + $last.name) $sitedir -ErrorAction Continue 2>>$global:errfile

      if ($site.name -eq "PSDSCPullServer") {
        FileVersion -Filepath ($path + "\bin\Microsoft.Powershell.DesiredStateConfiguration.Service.dll") -Log $true
        # GetFileVersion ($path + "\bin\Microsoft.Powershell.DesiredStateConfiguration.Service.dll")
        $docDSC = (Get-content ($path + "\web.config")) -as [xml]
        foreach ($conf in $docDSC.configuration.appSettings.add) {
          if ($conf.key -eq "dbconnectionstr") {
            $DSCDb = $conf.value
            Write-Log ("DSC dbconnectionstr = " + $DSCDb )
          }
        }
      }
    }
  }
 }

if (Test-Path -Path "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config") {
  Write-Log "Globabl web.config"
  Copy-Item "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config" ($global:resDir + "\global-web.config")
}

$dir = $env:windir + "\system32\logfiles\HTTPERR"
if (Test-Path -path $dir) {
  $last = Get-ChildItem -path ($dir) | Sort CreationTime -Descending | Select Name -First 1 
  Copy-Item ($dir + "\" + $last.name) $global:resDir\httperr.log -ErrorAction Continue 2>>$global:errfile
}

Write-Log "DISM logs"
Compress-Archive -Path ($env:windir + "\Logs\DISM") -DestinationPath ($global:resDir + "\dism.zip")

Write-Log "CBS logs"
Compress-Archive -Path ($env:windir + "\Logs\CBS") -DestinationPath ($global:resDir + "\cbs.zip")

if (Test-Path -Path "C:\Program Files\WindowsPowerShell\DscService\Devices.edb") {
  $cmd = "cmd.exe /c esentutl.exe /y """ + $DSCDb +  """ /vssrec"
  Write-Log $cmd
  Invoke-Expression $cmd
  Move-Item .\Devices.edb $global:resDir
}

Write-Log "DSC Configuration"
Copy-Item "C:\Windows\System32\Configuration" -Recurse $global:resDir

if (Test-Path -Path "C:\WindowsAzure\Logs\WaAppAgent.log") {
  Write-Log "Windows Azure Guest Agent log"
  Copy-Item "C:\WindowsAzure\Logs\WaAppAgent.log" ($global:resDir + "\WaAppAgent.log")
}

if (Test-Path -Path "C:\WindowsAzure\Logs\Plugins\Microsoft.Powershell.DSC") {
  Write-Log "Azure DSC Extension Logs"
  Copy-Item "C:\WindowsAzure\Logs\Plugins\Microsoft.Powershell.DSC" -Recurse ($global:resDir + "\AzureDSCLogs")
}

if (Test-Path -Path "C:\Packages\Plugins\Microsoft.Powershell.DSC") {
  Write-Log "Azure DSC Extension Package"
  Copy-Item "C:\Packages\Plugins\Microsoft.Powershell.DSC" -Recurse ($global:resDir + "\AzureDSCPackage")
}

if (Test-Path -Path "C:\Windows\Temp\ScriptLog.log") {
  Write-Log "Windows Virtual Desktop log"
  Copy-Item "C:\Windows\Temp\ScriptLog.log" ($global:resDir + "\WVD-ScriptLog.log")
}

if (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Azure\DSC") {
  Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure\DSC"
  $cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Azure\DSC """+ $global:resDir + "\AzureDSC.reg.txt"" /y >>""" + $global:outfile + """ 2>>""" + $global:errfile + """"
  Invoke-Expression $cmd
}

if (Test-Path -Path "C:\Program Files\WindowsPowerShell\DscService\Configuration") {
  Write-Log "DSC Service Configuration"
  New-Item -itemtype directory -path ($global:resDir + "\DscService") | Out-Null
  Copy-Item "C:\Program Files\WindowsPowerShell\DscService\Configuration" -Recurse ($global:resDir + "\DscService")
}

Write-Log "Installed certificates"
Get-ChildItem Cert:\LocalMachine\My\ | Out-File -FilePath ($global:resDir + "\CertLocalMachineMy.txt")

$tbCert = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Store,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn Thumbprint,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn Subject,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn Issuer,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn NotAfter,([DateTime]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn IssuerThumbprint,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn EnhancedKeyUsage,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn SerialNumber,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn SubjectKeyIdentifier,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn AuthorityKeyIdentifier,([string]); $tbCert.Columns.Add($col)
$col = New-Object system.Data.DataColumn Template,([string]); $tbCert.Columns.Add($col)

GetStore "My"
GetStore "CA"
GetStore "Root"

Write-Log "Matching issuer thumbprints"
$aCert = $tbCert.Select("Store = 'My' or Store = 'CA'")
foreach ($cert in $aCert) {
  $aIssuer = $tbCert.Select("SubjectKeyIdentifier = '" + ($cert.AuthorityKeyIdentifier).tostring() + "'")
  if ($aIssuer.Count -gt 0) {
    $cert.IssuerThumbprint = ($aIssuer[0].Thumbprint).ToString()
  }
}
$tbcert | Export-Csv ($global:resDir + "\certificates.tsv") -noType -Delimiter "`t"

Write-Log "Get-Module output"
Get-Module -ListAvailable | Out-File -FilePath ($global:resDir + "\Get-Module.txt")

Write-Log "Get-DscResource output"
Get-DscResource | Out-File -FilePath ($global:resDir + "\Get-DscResource.txt")

Write-Log "Get-DscLocalConfigurationManager output"
Get-DscLocalConfigurationManager | Out-File -FilePath ($global:resDir + "\Get-DscLocalConfigurationManager.txt")

try {
  Write-Log "Get-DscConfiguration output"
  Get-DscConfiguration | Out-File -FilePath ($global:resDir + "\Get-DscConfiguration.txt")
} 
catch {
  Write-Log "Get-DscConfiguration failed, DSC not configured on this machine?"
}

Write-Log "Get-DscConfigurationStatus output"
Get-DscConfigurationStatus -all 2>>$global:errfile | Out-File -FilePath ($global:resDir + "\Get-DscConfigurationStatus.txt")

$dir = $env:windir + "\system32\inetsrv"
if (Test-Path -Path ($dir + "\appcmd.exe")) {
  $cmd = $dir + "\appcmd list wp >""" + $global:resDir + "\IIS-WorkerProcesses.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append  

  $lines = Get-Content ($global:resDir + "\IIS-WorkerProcesses.txt")
  foreach ($line in $lines) {
    $aLine = $line.Split("""")
    if ($aLine[2] -match "applicationPool:PSWS") {
      CreateProcDump $aLine[1] $global:resDir "W3WP"
    }
  }
}

Write-Log "Get-WinSystemLocale output"
"Get-WinSystemLocale" | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append
Get-WinSystemLocale | Out-File -FilePath ($global:resDir + "\LanguageInfo.txt") -Append

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP"
$cmd = "reg export HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\HTTP """+ $global:resDir + "\HTTP.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting ipconfig /all output"
$cmd = "ipconfig /all >""" + $global:resDir + "\ipconfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Export-EventLog "Application"
Export-EventLog "System"
Export-EventLog "Microsoft-Windows-WMI-Activity/Operational"
Export-EventLog "Microsoft-Windows-DSC/Operational"
Export-EventLog "Microsoft-Windows-CAPI2/Operational"
Export-EventLog "Microsoft-Windows-Powershell-DesiredStateConfiguration-PullServer/Operational"
Export-EventLog "Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Operational"
Export-EventLog "Microsoft-Windows-ManagementOdataService/Operational"
Export-EventLog "Microsoft-Windows-PowerShell/Operational"
Export-EventLog "Microsoft-Windows-WinRM/Operational"

Write-Log "WinHTTP proxy configuration"
$cmd = "netsh winhttp show proxy >""" + $global:resDir + "\WinHTTP-Proxy.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "NSLookup WPAD"
"------------------" | Out-File -FilePath ($global:resDir + "\WinHTTP-Proxy.txt") -Append
"NSLookup WPAD" | Out-File -FilePath ($global:resDir + "\WinHTTP-Proxy.txt") -Append
"" | Out-File -FilePath ($global:resDir + "\WinHTTP-Proxy.txt") -Append
$cmd = "nslookup wpad >>""" + $global:resDir + "\WinHTTP-Proxy.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Collecting details about running processes"
if (ListProcsAndSvcs) {
  CollectSystemInfoWMI
  ExecQuery -Namespace "root\cimv2" -Query "select * from Win32_Product" | Sort-Object Name | Format-Table -AutoSize -Property Name, Version, Vendor, InstallDate | Out-String -Width 400 | Out-File -FilePath ($global:resDir + "\products.txt")

  Write-Log "Collecting the list of installed hotfixes"
  Get-HotFix -ErrorAction SilentlyContinue 2>>$global:errfile | Sort-Object -Property InstalledOn | Out-File $global:resDir\hotfixes.txt

  Write-Log "Collecing GPResult output"
  $cmd = "gpresult /h """ + $global:resDir + "\gpresult.html""" + $RdrErr
  write-log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

  $cmd = "gpresult /r >""" + $global:resDir + "\gpresult.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append
} else {
  Write-Log "WMI is not working"
  $proc = Get-Process | Where-Object {$_.Name -ne "Idle"}
  $proc | Format-Table -AutoSize -property id, name, @{N="WorkingSet";E={"{0:N0}" -f ($_.workingset/1kb)};a="right"},
  @{N="VM Size";E={"{0:N0}" -f ($_.VirtualMemorySize/1kb)};a="right"},
  @{N="Proc time";E={($_.TotalProcessorTime.ToString().substring(0,8))}}, @{N="Threads";E={$_.threads.count}},
  @{N="Handles";E={($_.HandleCount)}}, StartTime, Path | 
  Out-String -Width 300 | Out-File -FilePath ($global:resDir + "\processes.txt")
  CollectSystemInfoNoWMI
}