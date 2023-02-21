param( [string]$DataPath, [switch]$AcceptEula, [switch]$Trace )

$version = "WMI-Collect (20230221)"
# by Gianni Bragante - gbrag@microsoft.com

$DiagVersion = "WMI-RPC-DCOM-Diag (20230215)"
# by Marius Porcolean maporcol@microsoft.com

Function GetOwnerCim{
  param( $prc )
  $ret = Invoke-CimMethod -InputObject $prc -MethodName GetOwner
  return ($ret.Domain + "\" + $ret.User)
}

Function GetOwnerWmi{
  param( $prc )
  $ret = $prc.GetOwner()
  return ($ret.Domain + "\" + $ret.User)
}

Function Write-LogMessage {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Message,

        [Parameter()]
        [ValidateSet('Error', 'Warning', 'Pass', 'Info')]
        [string] $Type = $null
    )
    
    $Color = $null
    switch ($Type) {
        "Error" {
            $Message = (Get-Date).ToString("yyyyMMdd-HH:mm:ss.fff") + "    " + "[ERROR]   " + $Message
            $Color = 'Magenta'
        }
        "Warning" {
            $Message = (Get-Date).ToString("yyyyMMdd-HH:mm:ss.fff") + "    " + "[WARNING] " + $Message
            $Color = 'Yellow'
        }
        "Pass" {
            $Message = (Get-Date).ToString("yyyyMMdd-HH:mm:ss.fff") + "    " + "[PASS]    " + $Message
            $Color = 'Green'
        }
        Default {
            $Message = (Get-Date).ToString("yyyyMMdd-HH:mm:ss.fff") + "    " + "[INFO]    " + $Message
        }
    }
    if ([string]::IsNullOrEmpty($Color)) {
        Write-Host $Message
    } 
    else {
        Write-Host $Message -ForegroundColor $Color
    }
    if (!($NoLogFile)) {
        $Message | Out-File -FilePath $diagfile -Append
    }
}

Function WMITraceCapture {
  Invoke-CustomCommand ("logman create trace 'wmi-trace' -ow -o '" + $global:resDir + "\WMI-Trace-$env:COMPUTERNAME.etl" + "' -p 'Microsoft-Windows-WMI' 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets")

  # WMI-Activity
  Invoke-CustomCommand ("logman update trace 'wmi-trace' -p '{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}' 0xffffffffffffffff 0xff -ets")

  # Microsoft-Windows-WMIAdapter
  Invoke-CustomCommand ("logman update trace 'wmi-trace' -p '{2CF953C0-8DF7-48E1-99B9-6816A2FBDC9F}' 0xffffffffffffffff 0xff -ets")
  #logman update trace "wmi-trace" -p "{2CF953C0-8DF7-48E1-99B9-6816A2FBDC9F}" 0xffffffffffffffff 0xff -ets

  # WMI_Tracing
  Invoke-CustomCommand ("logman update trace 'wmi-trace' -p '{1FF6B227-2CA7-40F9-9A66-980EADAA602E}' 0xffffffffffffffff 0xff -ets")
  #logman update trace "wmi-trace" -p "{1FF6B227-2CA7-40F9-9A66-980EADAA602E}" 0xffffffffffffffff 0xff -ets

  # WMI_Tracing_Client_Operations_Info_Guid
  Invoke-CustomCommand ("logman update trace 'wmi-trace' -p '{8E6B6962-AB54-4335-8229-3255B919DD0E}' 0xffffffffffffffff 0xff -ets")
  #logman update trace "wmi-trace" -p "{8E6B6962-AB54-4335-8229-3255B919DD0E}" 0xffffffffffffffff 0xff -ets

  Write-Log "Trace capture started"
  read-host “Press ENTER to stop the capture”
  Invoke-CustomCommand "logman stop 'wmi-trace' -ets"
  Invoke-CustomCommand "tasklist /svc" -DestinationFile "tasklist-$env:COMPUTERNAME.txt"
}

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

$global:Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path
$resName = "WMI-Results-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)

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
$diagfile = $global:resDir + "\WMI-RPC-DCOM-Diag.txt"

Import-Module ($global:Root + "\Collect-Commons.psm1") -Force -DisableNameChecking

Write-Log $version
if ($AcceptEula) {
  Write-Log "AcceptEula switch specified, silently continuing"
  $eulaAccepted = ShowEULAIfNeeded "WMI-Collect" 2
} else {
  $eulaAccepted = ShowEULAIfNeeded "WMI-Collect" 0
  if($eulaAccepted -ne "Yes")
   {
     Write-Log "EULA declined, exiting"
     exit
   }
 }
Write-Log "EULA accepted, continuing"

if ($Trace) {
  WMITraceCapture
  exit
}

$subDir = $global:resDir + "\Subscriptions"
New-Item -itemtype directory -path $subDir | Out-Null

Write-Log "Collecting dump of the svchost process hosting the WinMgmt service"
$pidsvc = FindServicePid "winmgmt"
if ($pidsvc) {
  Write-Log "Found the PID using FindServicePid"
  CreateProcDump $pidsvc $global:resDir "scvhost-WinMgmt"
} else {
  Write-Log "Cannot find the PID using FindServicePid, looping through processes"
  $list = Get-Process
  $found = $false
  if (($list | Measure-Object ).count -gt 0) {
    foreach ($proc in $list) {
      $prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "wmisvc.dll"} 
      if (($prov | Measure-Object).count -gt 0) {
        Write-Log "Found the PID having wmisvc.dll loaded"
        CreateProcDump $proc.id $global:resDir "scvhost-WinMgmt"
        $found = $true
        break
      }
    }
  }
  if (-not $found) {
    Write-Log "Cannot find any process having wmisvc.dll loaded, probably the WMI service is not running"
  }
}

Write-Log "Collecing the dumps of WMIPrvSE.exe processes"
$list = get-process -Name "WmiPrvSe" -ErrorAction SilentlyContinue 2>>$global:errfile
if (($list | Measure-Object).count -gt 0) {
  foreach ($proc in $list)
  {
    Write-Log ("Found WMIPrvSE.exe with PID " + $proc.Id)
    CreateProcDump $proc.id $global:resDir
  }
} else {
  Write-Log "No WMIPrvSE.exe processes found"
}

Write-Log "Collecing the dumps of decoupled WMI providers"
$list = Get-Process
if (($list | Measure-Object).count -gt 0) {
  foreach ($proc in $list)
  {
    $prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "wmidcprv.dll"} 
    if (($prov | Measure-Object).count -gt 0) {
      Write-Log ("Found " + $proc.Name + "(" + $proc.id + ")")
      CreateProcDump $proc.id $global:resDir
    }
  }
}

$proc = get-process "WmiApSrv" -ErrorAction SilentlyContinue
if ($proc) {
  Write-Log "Collecting dump of the WmiApSrv.exe process"
  CreateProcDump $proc.id $global:resDir
}

Write-Log "Collecing the dumps of scrcons.exe processes"
$list = get-process -Name "scrcons" -ErrorAction SilentlyContinue 2>>$global:errfile
if (($list | Measure-Object).count -gt 0) {
  foreach ($proc in $list)
  {
    CreateProcDump $proc.id $global:resDir
  }
} else {
  Write-Log "No scrcons.exe processes found"
}

Write-Log "Collecting Autorecover MOFs content"
$mof = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM")).'Autorecover MOFs'
if ($mof.length -eq 0) {
  Write-Log ("The registry key ""HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM\Autorecover MOFs"" is missing or empty")
  exit
}
$mof | Out-File ($global:resDir + "\Autorecover MOFs.txt")

Write-Log "Listing WBEM folder"
Get-ChildItem $env:windir\system32\wbem -Recurse | Out-File $global:resDir\wbem.txt

Write-Log "Exporting WMIPrvSE AppIDs and CLSIDs registration keys"
$cmd = "reg query ""HKEY_CLASSES_ROOT\AppID\{73E709EA-5D93-4B2E-BBB0-99B7938DA9E4}"" >> """ + $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
$cmd = "reg query ""HKEY_CLASSES_ROOT\AppID\{1F87137D-0E7C-44d5-8C73-4EFFB68962F2}"" >> """+ $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
$cmd = "reg query ""HKEY_CLASSES_ROOT\Wow6432Node\AppID\{73E709EA-5D93-4B2E-BBB0-99B7938DA9E4}"" >> """+ $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
$cmd = "reg query ""HKEY_CLASSES_ROOT\Wow6432Node\AppID\{1F87137D-0E7C-44d5-8C73-4EFFB68962F2}"" >> """+ $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
$cmd = "reg query ""HKEY_CLASSES_ROOT\CLSID\{4DE225BF-CF59-4CFC-85F7-68B90F185355}"" >> """+ $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole """+ $global:resDir + "\Ole.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Rpc"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Rpc """+ $global:resDir + "\Rpc.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Invoke-Expression $cmd

if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc") {
  Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
  $cmd = "reg export ""HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"" """ + $global:resDir + "\Rpc-policies.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $global:errfile + """"
  Invoke-Expression $cmd
}

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Wbem"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Wbem """+ $global:resDir + "\wbem.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Invoke-Expression $cmd

# SCCM automatic remediation exclusion, see https://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/configure-client-status#automatic-remediation-exclusion
Export-RegistryKey -KeyPath "HKLM:\Software\Microsoft\CCM\CcmEval" -DestinationFile "CCMEval.txt"

Write-Log "Getting the output of WHOAMI /all"
$cmd = "WHOAMI /all >>""" + $global:resDir + "\WHOAMI.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Exporting Application log"
$cmd = "wevtutil epl Application """+ $global:resDir + "\" + $env:computername + "-Application.evtx"" >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "Application"

Write-Log "Exporting System log"
$cmd = "wevtutil epl System """+ $global:resDir + "\" + $env:computername + "-System.evtx"" >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "System"

Write-Log "Exporting WMI-Activity/Operational log"
$cmd = "wevtutil epl Microsoft-Windows-WMI-Activity/Operational """+ $global:resDir + "\" + $env:computername + "-WMI-Activity.evtx"" >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "WMI-Activity"

if ($PSVersionTable.psversion.ToString() -ge "3.0") {
  $actLog = Get-WinEvent -logname Microsoft-Windows-WMI-Activity/Operational -Oldest -ErrorAction Continue 2>>$global:errfile
  if (($actLog  | Measure-Object).count -gt 0) {
    Write-Log "Exporting WMI-Activity log"
    $actLog | Out-String -width 1000 | Out-File -FilePath ($global:resDir + "\WMI-Activity.txt")
  }
}

Write-Log "Exporting netstat output"
$cmd = "netstat -anob >""" + $global:resDir + "\netstat.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Exporting ipconfig /all output"
$cmd = "ipconfig /all >""" + $global:resDir + "\ipconfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Exporting firewall rules"
$cmd = "netsh advfirewall firewall show rule name=all >""" + $global:resDir + "\FirewallRules.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Exporting service configuration"
$cmd = "sc.exe queryex winmgmt >>""" + $global:resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

$cmd = "sc.exe qc winmgmt >>""" + $global:resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

$cmd = "sc.exe enumdepend winmgmt 3000 >>""" + $global:resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

$cmd = "sc.exe sdshow winmgmt >>""" + $global:resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

FileVersion -Filepath ($env:windir + "\system32\wbem\wbemcore.dll") -Log $true
FileVersion -Filepath ($env:windir + "\system32\wbem\repdrvfs.dll") -Log $true
FileVersion -Filepath ($env:windir + "\system32\wbem\WmiPrvSE.exe") -Log $true
FileVersion -Filepath ($env:windir + "\system32\wbem\WmiPerfClass.dll") -Log $true
FileVersion -Filepath ($env:windir + "\system32\wbem\WmiApRpl.dll") -Log $true

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

  Write-Log "COM Security"
  $Reg = [WMIClass]"\\.\root\default:StdRegProv"
  $DCOMMachineLaunchRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineLaunchRestriction").uValue
  $DCOMMachineAccessRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineAccessRestriction").uValue
  $DCOMDefaultLaunchPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultLaunchPermission").uValue
  $DCOMDefaultAccessPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultAccessPermission").uValue

  # Convert the current permissions to SDDL
  $converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
  "Default Access Permission = " + ($converter.BinarySDToSDDL($DCOMDefaultAccessPermission)).SDDL | Out-File -FilePath ($global:resDir + "\COMSecurity.txt") -Append
  "Default Launch Permission = " + ($converter.BinarySDToSDDL($DCOMDefaultLaunchPermission)).SDDL | Out-File -FilePath ($global:resDir + "\COMSecurity.txt") -Append
  "Machine Access Restriction = " + ($converter.BinarySDToSDDL($DCOMMachineAccessRestriction)).SDDL | Out-File -FilePath ($global:resDir + "\COMSecurity.txt") -Append
  "Machine Launch Restriction = " + ($converter.BinarySDToSDDL($DCOMMachineLaunchRestriction)).SDDL | Out-File -FilePath ($global:resDir + "\COMSecurity.txt") -Append

  Write-Log "Collecting details of provider hosts"
  New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR -ErrorAction SilentlyContinue | Out-Null

  "Coupled providers (WMIPrvSE.exe processes)" | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
  "" | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append

  $totMem = 0
  $prov = ExecQuery -NameSpace "root\cimv2" -Query "select HostProcessIdentifier, Provider, Namespace, User from MSFT_Providers"
  if ($prov) {
    $proc = ExecQuery -NameSpace "root\cimv2" -Query "select ProcessId, HandleCount, ThreadCount, PrivatePageCount, CreationDate, KernelModeTime, UserModeTime from Win32_Process where name = 'wmiprvse.exe'"
    foreach ($prv in $proc) {
      $provhost = $prov | Where-Object {$_.HostProcessIdentifier -eq $prv.ProcessId}

      if (($provhost | Measure-Object).count -gt 0) {
        if ($PSVersionTable.psversion.ToString() -ge "3.0") {
          $ut = New-TimeSpan -Start $prv.CreationDate
        } else {
          $ut = New-TimeSpan -Start $prv.ConvertToDateTime($prv.CreationDate)
        }

        $uptime = ($ut.Days.ToString() + "d " + $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00"))

        $ks = $prv.KernelModeTime / 10000000
        $kt = [timespan]::fromseconds($ks)
        $kh = $kt.Hours.ToString("00") + ":" + $kt.Minutes.ToString("00") + ":" + $kt.Seconds.ToString("00")

        $us = $prv.UserModeTime / 10000000
        $ut = [timespan]::fromseconds($us)
        $uh = $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00")

        "PID" + " " + $prv.ProcessId + " (" + [String]::Format("{0:x}", $prv.ProcessId) + ") Handles:" + $prv.HandleCount +" Threads:" + $prv.ThreadCount + " Private KB:" + ($prv.PrivatePageCount/1kb) + " KernelTime:" + $kh + " UserTime:" + $uh + " Uptime:" + $uptime + " " + (Get-ProcBitness($prv.ProcessId)) | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
        $totMem = $totMem + $prv.PrivatePageCount
      } else {
        Write-Log ("No provider found for the WMIPrvSE process with PID " +  $prv.ProcessId)
      }

      foreach ($provname in $provhost) {
        $provdet = ExecQuery -NameSpace $provname.Namespace -Query ("select * from __Win32Provider where Name = """ + $provname.Provider + """")
        $hm = $provdet.hostingmodel
        $clsid = $provdet.CLSID
        $dll = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKCR:\CLSID\" + $clsid + "\InprocServer32")).'(default)' 2>>$global:errfile
        $dll = $dll.Replace("""","")
        $file = Get-Item ($dll)
        $dtDLL = $file.CreationTime
        $verDLL = $file.VersionInfo.FileVersion

        $provname.Namespace + " " + $provname.Provider + " " + $dll + " " + $hm + " " + $provname.user + " " + $dtDLL + " " + $verDLL 2>>$global:errfile | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
      }
      " " | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
    }
  }
  "Total memory used by coupled providers: " + ($totMem/1kb) + " KB" | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
  " " | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append

  # Details of decoupled providers
  $list = Get-Process
  foreach ($proc in $list) {
    $prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "wmidcprv.dll"} 
    if (($prov | Measure-Object).count -gt 0) {
      if (-not $hdr) {
        "Decoupled providers" | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
        " " | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
        $hdr = $true
      }

      $prc = ExecQuery -Namespace "root\cimv2" -Query ("select ProcessId, CreationDate, HandleCount, ThreadCount, PrivatePageCount, ExecutablePath, KernelModeTime, UserModeTime from Win32_Process where ProcessId = " +  $proc.id)
      if ($PSVersionTable.psversion.ToString() -ge "3.0") {
        $ut= New-TimeSpan -Start $prc.CreationDate
      } else {
        $ut= New-TimeSpan -Start $prc.ConvertToDateTime($prc.CreationDate)
      }

      $uptime = ($ut.Days.ToString() + "d " + $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00"))

      $ks = $prc.KernelModeTime / 10000000
      $kt = [timespan]::fromseconds($ks)
      $kh = $kt.Hours.ToString("00") + ":" + $kt.Minutes.ToString("00") + ":" + $kt.Seconds.ToString("00")

      $us = $prc.UserModeTime / 10000000
      $ut = [timespan]::fromseconds($us)
      $uh = $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00")

      $svc = ExecQuery -Namespace "root\cimv2" -Query ("select Name from Win32_Service where ProcessId = " +  $prc.ProcessId)
      $svclist = ""
      if ($svc) {
        foreach ($item in $svc) {
          $svclist = $svclist + $item.name + " "
        }
        $svc = " Service: " + $svclist
      } else {
        $svc = ""
      }

      ($prc.ExecutablePath + $svc) | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
      "PID " + $prc.ProcessId  + " (" + [String]::Format("{0:x}", $prc.ProcessId) + ")  Handles: " + $prc.HandleCount + " Threads: " + $prc.ThreadCount + " Private KB: " + ($prc.PrivatePageCount/1kb) + " KernelTime:" + $kh + " UserTime:" + $uh + " Uptime:" + $uptime + " " + (Get-ProcBitness($prv.ProcessId)) | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append

      $Keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Wbem\Transports\Decoupled\Client
      $Items = $Keys | Foreach-Object {Get-ItemProperty $_.PsPath }
      ForEach ($key in $Items) {
        if ($key.ProcessIdentifier -eq $prc.ProcessId) {
          ($key.Scope + " " + $key.Provider) | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
        }
      }
      " " | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
    }
  }

  Write-Log "Collecting quota details"
  $quota = ExecQuery -Namespace "Root" -Query "select * from __ProviderHostQuotaConfiguration"
  if ($quota) {
    ("ThreadsPerHost : " + $quota.ThreadsPerHost + "`r`n") + `
    ("HandlesPerHost : " + $quota.HandlesPerHost + "`r`n") + `
    ("ProcessLimitAllHosts : " + $quota.ProcessLimitAllHosts + "`r`n") + `
    ("MemoryPerHost : " + $quota.MemoryPerHost + "`r`n") + `
    ("MemoryAllHosts : " + $quota.MemoryAllHosts + "`r`n") | Out-File -FilePath ($global:resDir + "\ProviderHostQuotaConfiguration.txt")
  }

  ExecQuery -Namespace "root\subscription" -Query "select * from ActiveScriptEventConsumer" | Export-Clixml -Path ($subDir + "\ActiveScriptEventConsumer.xml")
  ExecQuery -Namespace "root\subscription" -Query "select * from __eventfilter" | Export-Clixml -Path ($subDir + "\__eventfilter.xml")
  ExecQuery -Namespace "root\subscription" -Query "select * from __IntervalTimerInstruction" | Export-Clixml -Path ($subDir + "\__IntervalTimerInstruction.xml")
  ExecQuery -Namespace "root\subscription" -Query "select * from __AbsoluteTimerInstruction" | Export-Clixml -Path ($subDir + "\__AbsoluteTimerInstruction.xml")
  ExecQuery -Namespace "root\subscription" -Query "select * from __FilterToConsumerBinding" | Export-Clixml -Path ($subDir + "\__FilterToConsumerBinding.xml")

  Write-Log "Exporting driverquery /v output"
  $cmd = "driverquery /v >""" + $global:resDir + "\drivers.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append
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

Write-LogMessage ($DiagVersion)

####################################################################################
#################################### Diag start ####################################
####################################################################################

# Check OS version & get IPs
$OSVer = [environment]::OSVersion.Version.Major + [environment]::OSVersion.Version.Minor * 0.1
if ($OSVer -gt 6.1) {

    $versionRegKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    Write-LogMessage "Host: $($env:COMPUTERNAME)"
    Write-LogMessage "Running on: $($versionRegKey.ProductName)"
    Write-LogMessage "Current build number: $($versionRegKey.CurrentBuildNumber).$($versionRegKey.UBR)"
    Write-LogMessage "Build details: $($versionRegKey.BuildLabEx)"

    # TODO - try to determine when the last patch was installed...not the best option...
    # tried getting the last write time of the build number in the registry, but that's not possible... 
    # can only get a LastWriteTime for a regkey, not for a regvalue
    # https://devblogs.microsoft.com/scripting/use-powershell-to-access-registry-last-modified-time-stamp/
    $xmlQuery = @'
    <QueryList>
        <Query Id="0" Path="Setup">
            <Select Path="Setup">*[System[(EventID=2)]][UserData[CbsPackageChangeState[(Client='UpdateAgentLCU' or Client='WindowsUpdateAgent') and (ErrorCode='0x0')]]]</Select>
        </Query>
    </QueryList>
'@
    $lastSuccessfulPatch = Get-WinEvent -MaxEvents 1 -FilterXml $xmlQuery  -ErrorAction SilentlyContinue
    if ($lastSuccessfulPatch) {
        if ($lastSuccessfulPatch.TimeCreated -le ((Get-Date).AddDays(-90))) {
            Write-LogMessage -Type Warning "This device looks like it may not have been patched recently. Check current build number ($($versionRegKey.UBR)) vs the build number of the latest patches."
        }
        Write-LogMessage "The most recent successfully installed patch was $($lastSuccessfulPatch.Properties[0].Value), $(((Get-Date) - $lastSuccessfulPatch.TimeCreated).Days) days ago @ $($lastSuccessfulPatch.TimeCreated)."
    }
    else {
        Write-LogMessage -Type Warning "Could not detect any successful patching events. Check current build number ($($versionRegKey.UBR)) vs the build number of the latest patches."
    }

    $psver = $PSVersionTable.PSVersion.Major.ToString() + $PSVersionTable.PSVersion.Minor.ToString()
    if ($psver -lt "51") {
        Write-LogMessage -Type Warning "Windows Management Framework version $($PSVersionTable.PSVersion.ToString()) is no longer supported"
    }
    else { 
        Write-LogMessage "Windows Management Framework version is $($PSVersionTable.PSVersion.ToString())"
    }
    Write-LogMessage "Running PowerShell build $($PSVersionTable.BuildVersion.ToString())"

    $iplist = Get-NetIPAddress
    Write-LogMessage "IP addresses of this machine: $(foreach ($ip in $iplist) {$ip.ToString() +' |'})"
}
else {
    Write-LogMessage -Type Warning "This is a legacy OS, please consider updating to a newer supported version."
}


Write-LogMessage "-------------------------"
Write-LogMessage "Checking services..."

# check WMI, RPCSS, DcomLaunch services
$services = Get-Service EventSystem, COMSysApp, RPCSS, RpcEptMapper, DcomLaunch, Winmgmt
if ($services) {
    foreach ($service in $Services) {
        $msg = "The '$($service.DisplayName)' service is $($service.Status)."
        if ($service.Status -eq 'Running') {
            Write-LogMessage -Type Pass $msg
        }
        else {
            Write-LogMessage -Type Error $msg
        }
        if (($service.Name -eq 'COMSysApp') -and ($service.StartType -ne 'Manual')) {
            Write-LogMessage -Type Warning "The service also does not have its default StartupType. Default: Manual. Current setting: $($service.StartType)."
        }
        elseif (($service.Name -ne 'COMSysApp') -and ($service.StartType -ne 'Automatic')) {
            Write-LogMessage -Type Warning "The service also does not have its default StartupType. Default: Automatic. Current setting: $($service.StartType)."
        }
    }
}
else {
    Write-LogMessage -Type Error "Could not check the status of the services, please look into this!"
}   


Write-LogMessage "-------------------------"
Write-LogMessage "Checking COM+ settings..."

# Check if COM+ is on
$enableComPlus = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\COM3").'Com+Enabled'
if ([string]::IsNullOrEmpty($enableComPlus)) {
    Write-LogMessage -Type Warning "Could not check COM+, please check manually @ HKLM:\SOFTWARE\Microsoft\COM3."
}
else {
    if ($enableComPlus -eq 1) {
        Write-LogMessage -Type Pass "COM+ is enabled."
    }
    elseif ($enableComPlus -eq 0) {
        Write-LogMessage -Type Error "COM+ is NOT enabled."
    }
}

# Check if COM+ remote access is on
$remoteComPlus = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\COM3").RemoteAccessEnabled
if ([string]::IsNullOrEmpty($remoteComPlus)) {
    Write-LogMessage -Type Warning "Could not check COM+ remote access, please check manually @ HKLM:\SOFTWARE\Microsoft\COM3."
}
else {
    if ($remoteComPlus -eq 1) {
        Write-LogMessage -Type Warning "COM+ remote access is enabled. By default it is off."
    }
    elseif ($remoteComPlus -eq 0) {
        Write-LogMessage -Type Pass "COM+ remote access is not enabled. This is ok, by default it is off."
    }
}


Write-LogMessage "-------------------------"
Write-LogMessage "Checking RPC settings..."

# Check if the Restrict Unauthenticated RPC clients policy is on or not
$restrictRpcClients = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -ErrorAction SilentlyContinue).RestrictRemoteClients
if ([string]::IsNullOrEmpty($restrictRpcClients)) {
    Write-LogMessage -Type Pass "RPC restrictions via policy are not in place."
}
else {
    switch ($restrictRpcClients) {
        0 { Write-LogMessage "The RPC restriction policy is set to 'None', so all connections are allowed." }
        1 { Write-LogMessage "The RPC restriction policy is set to 'Authenticated', so only Authenticated RPC Clients are allowed. Exemptions are granted to interfaces that have requested them." }
        2 { Write-LogMessage -Type Warning "The RPC restriction policy is set to 'Authenticated without exceptions', so only Authenticated RPC Clients are allowed, with NO exceptions. This is known to cause on the client some very tricky to investigate 'access denied' errors." }
        Default { Write-LogMessage -Type Error "The RPC restriction policy seems to be present, but its value seems to be wrong. It should be 0, 1 or 2, but is actually $($restrictRpcClients)." }
    }
}

# Check if RPC Endpoint Mapper Client Authentication is on or not
$authEpResolution = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -ErrorAction SilentlyContinue).EnableAuthEpResolution
if (([string]::IsNullOrEmpty($authEpResolution)) -or ($authEpResolution -eq 0)) {
    Write-LogMessage -Type Pass "RPC Endpoint Mapper Client Authentication is not configured or disabled."
}
elseif ($authEpResolution -eq 1) {
    Write-LogMessage -Type Warning "RPC Endpoint Mapper Client Authentication is enabled, which may cause some issues with applications/components that do not know how to handle this."
}

# Check internet settings for RPC to see if there's a restricted port range
$rpcPortsRestriction = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Rpc\Internet" -ErrorAction SilentlyContinue).UseInternetPorts
if (([string]::IsNullOrEmpty($rpcPortsRestriction)) -or ($rpcPortsRestriction -eq "N")) {
    Write-LogMessage -Type Pass "RPC ports are not restricted."
}
elseif ($rpcPortsRestriction -eq "Y") {
    $rpcPorts = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Rpc\Internet" -ErrorAction SilentlyContinue).Ports
    Write-LogMessage -Type Warning "RPC ports are restricted. This may cause issues with RPC/DCOM connections. The usable port range is defined to '$($rpcPorts.ToString())'."
}

# Check actual dynamic port range
$intSettings = Get-NetTCPSetting -SettingName Internet
if ($null -eq $intSettings) {
    Write-LogMessage -Type Warning "The Internet TCP dynamic port range could not be read, please have a close look."
}
elseif ($intSettings.DynamicPortRangeStartPort -eq 49152 -and $intSettings.DynamicPortRangeNumberOfPorts -eq 16384) {
    Write-LogMessage -Type Pass "The Internet TCP dynamic port range is the default."
}
else {
    Write-LogMessage -Type Warning "The Internet TCP dynamic port range is NOT the default, please have a closer look."
}


Write-LogMessage "-------------------------"
Write-LogMessage "Checking DCOM settings..."

# Check if DCOM is enabled 
$ole = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole"
if ($ole.EnableDCOM -eq "Y") {
    Write-LogMessage -Type Pass "DCOM is enabled."
}
else {
    Write-LogMessage -Type Error "DCOM is NOT enabled! Check the settings."
}

# Check default DCOM Launch & Activation / Access permissions
$defaultPermissions = @(
    @{
        name   = 'Everyone'
        short  = 'WD'
        sid    = 'S-1-1-0'
        launch = 'A;;CCDCSW;;;' 
        access = 'A;;CCDCLC;;;'
    }
    @{
        name   = 'Administrators'
        short  = 'BA'
        sid    = 'S-1-5-32-544'
        launch = 'A;;CCDCLCSWRP;;;'
    }
    @{
        name   = 'Distributed COM Users'
        short  = 'CD'
        sid    = 'S-1-5-32-562'
        launch = 'A;;CCDCLCSWRP;;;'
        access = 'A;;CCDCLC;;;'
    }
    @{
        name   = 'Performance Log Users'
        short  = 'LU'
        sid    = 'S-1-5-32-559'
        launch = 'A;;CCDCLCSWRP;;;'
        access = 'A;;CCDCLC;;;'
    }
    @{
        name   = 'All Application Packages'
        short  = 'AC'
        sid    = 'S-1-15-2-1'
        launch = 'A;;CCDCSW;;;'
        access = 'A;;CCDC;;;'
    }
)

# Get current permissions from registry
$launchRestriction = (([wmiclass]"Win32_SecurityDescriptorHelper").BinarySDToSDDL($ole.MachineLaunchRestriction)).SDDL
$accessRestriction = (([wmiclass]"Win32_SecurityDescriptorHelper").BinarySDToSDDL($ole.MachineAccessRestriction)).SDDL

# Compare current vs default permissions
foreach ($permission in $defaultPermissions.GetEnumerator()) {
    if ($permission.launch) {
        if ($launchRestriction.Contains($permission.launch + $permission.short) -or $launchRestriction.Contains($permission.launch + $permission.sid)) {
            Write-LogMessage -Type Pass "The '$($permission.name)' group is present in Launch & Activation with default permissions."
        }
        else {
            Write-LogMessage -Type Error "The '$($permission.name)' group is NOT present in Launch & Activation with default permissions, please verify."
        }
    }

    if ($permission.access) {
        if ($accessRestriction.Contains($permission.access + $permission.short) -or $accessRestriction.Contains($permission.access + $permission.sid)) {
            Write-LogMessage -Type Pass "The '$($permission.name)' group is present in Access with default permissions."
        }
        else {
            Write-LogMessage -Type Error "The '$($permission.name)' group is NOT present in Access with default permissions, please verify."
        }
    }
}

# Check enabled DCOM protocols
$protocols = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Rpc" -ErrorAction SilentlyContinue).'DCOM Protocols'
if ([string]::IsNullOrEmpty($protocols)) {
    Write-LogMessage -Type Warning "No protocols specified for DCOM."
}
else {
    Write-LogMessage "Enabled protocols: $($protocols)"
    if ($protocols.Contains("ncacn_ip_tcp")) {
        Write-LogMessage -Type Pass "The list of enabled protocols contains 'ncacn_ip_tcp', which should be present by default."
    }
    else {
        Write-LogMessage -Type Error "The list of enabled protocols does NOT contain 'ncacn_ip_tcp', which should be present by default."
    }
}

# Check DcomScmRemoteCallFlags
if ([string]::IsNullOrEmpty($ole.DCOMSCMRemoteCallFlags)) {
    Write-LogMessage -Type Pass "DCOMSCMRemoteCallFlags is not configured in the registry and by default it should not be there. That is ok."
}
else {
    Write-LogMessage -Type Warning "DCOMSCMRemoteCallFlags is configured in the registry with value '$($ole.DCOMSCMRemoteCallFlags)', while it should not be there by default. This does not necessarily mean there is a problem, nevertheless, please check the documentation:`nhttps://learn.microsoft.com/en-us/windows/win32/com/dcomscmremotecallflags"
}

# Check LegacyAuthenticationLevel
if ([string]::IsNullOrEmpty($ole.LegacyAuthenticationLevel)) {
    Write-LogMessage -Type Pass "LegacyAuthenticationLevel is not configured in the registry, so the default is used. That is ok."
}
else {
    Write-LogMessage -Type Warning "LegacyAuthenticationLevel is configured in the registry with value '$($ole.LegacyAuthenticationLevel)', while it should not be there by default. This should not be a problem, though, as we are raising the authentication level in the OS anyway, due to the DCOM hardening. Nevertheless, please check the documentation:`nhttps://learn.microsoft.com/en-us/windows/win32/com/legacyauthenticationlevel"
}

# Check LegacyImpersonationLevel
if ([string]::IsNullOrEmpty($ole.LegacyImpersonationLevel) -or ($ole.LegacyImpersonationLevel -eq 2)) {
    Write-LogMessage -Type Pass "LegacyImpersonationLevel is using the default value. That is ok."
}
else {
    Write-LogMessage -Type Warning "LegacyImpersonationLevel is configured in the registry with value '$($ole.LegacyImpersonationLevel)', while it should be '2' by default. Please check the documentation:`nhttps://learn.microsoft.com/en-us/windows/win32/com/legacyimpersonationlevel"
}

# Check DCOM hardening registry keys
$requireIntegrityAuthLevel = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole\AppCompat" -ErrorAction SilentlyContinue).RequireIntegrityActivationAuthenticationLevel
if ([string]::IsNullOrEmpty($requireIntegrityAuthLevel)) {
    Write-LogMessage -Type Pass "RequireIntegrityActivationAuthenticationLevel is not set in the registry. That is ok."
}
else {
    Write-LogMessage -Type Warning "RequireIntegrityActivationAuthenticationLevel is set in the registry to '$requireIntegrityAuthLevel'. Check info in public KB5004442.`nhttps://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c"
}

$raiseAuthLevel = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole\AppCompat" -ErrorAction SilentlyContinue).RaiseActivationAuthenticationLevel
if ([string]::IsNullOrEmpty($raiseAuthLevel)) {
    Write-LogMessage -Type Pass "RaiseActivationAuthenticationLevel is not set in the registry. That is ok."
}
else {
    Write-LogMessage -Type Warning "RaiseActivationAuthenticationLevel is set in the registry to '$raiseAuthLevel'. Check info in public KB5004442.`nhttps://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c"
}

$disableHardeningLogging = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole\AppCompat" -ErrorAction SilentlyContinue).DisableAuthenticationLevelHardeningLog
if ([string]::IsNullOrEmpty($disableHardeningLogging) -or ($disableHardeningLogging -eq 0)) {
    Write-LogMessage -Type Pass "Hardening related logging is turned on. That is ok, it should be on by default."
}
else {
    Write-LogMessage -Type Error "Hardening related logging is turned off. This is a problem, because you may have failing DCOM calls which you are not aware of. Please turn the logging back on by removing the DisableAuthenticationLevelHardeningLog entry from regkey 'HKLM:\SOFTWARE\Microsoft\Ole\AppCompat'."
}

# Check for any DCOM hardening events (IDs 10036/10037/10038)
$sysEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    ID      = 10036, 10037, 10038
} -ErrorAction SilentlyContinue
if (!$sysEvents) {
    Write-LogMessage -Type Pass "Did not detect any DCOM hardening related events (10036, 10037, 10038) in the System log."
}
else {
    if ($sysEvents.Id.Contains(10036)) {
        Write-LogMessage -Type Warning "Events with ID 10036 detected in the System event log. This device seems to be acting as a DCOM server & is rejecting some incoming connections, please check."
        
        # Print the most recent 5 of them
        Write-LogMessage "Here are the most recent ones:"
        foreach ($event in ($sysEvents | Where-Object { $_.Id -eq 10036 } | Select-Object -First 5)) {
            Write-LogMessage "$($event.TimeCreated) - $($event.Message)"
        }
    }
    if ($sysEvents.Id.Contains(10037)) {
        Write-LogMessage -Type Warning "Events with ID 10037 detected in the System event log. This device seems to be acting as a DCOM client with explicitly set auth level & failing, please check."
          
        # Print the most recent 5 of them
        Write-LogMessage "Here are the most recent ones:"
        foreach ($event in ($sysEvents | Where-Object { $_.Id -eq 10037 } | Select-Object -First 5)) {
            Write-LogMessage "$($event.TimeCreated) - $($event.Message)"
        }
    }
    if ($sysEvents.Id.Contains(10038)) {
        Write-LogMessage -Type Warning "Events with ID 10038 detected in the System event log. This device seems to be acting as a DCOM client with default auth level & failing, please check."
    
        # Print the most recent 5 of them
        Write-LogMessage "Here are the most recent ones:"
        foreach ($event in ($sysEvents | Where-Object { $_.Id -eq 10038 } | Select-Object -First 5)) {
            Write-LogMessage "$($event.TimeCreated) - $($event.Message)"
        }
    }
}


Write-LogMessage "-------------------------"
Write-LogMessage "Checking WMI settings..."

# Check WMI object permissions
New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR -ErrorAction SilentlyContinue | Out-Null
$comWmiObj = Get-ItemProperty -Path "HKCR:\AppID\{8BC3F05E-D86B-11D0-A075-00C04FB68820}" -ErrorAction SilentlyContinue
if (!$comWmiObj) {
    Write-LogMessage -Type Warning "Could not read the permissions for the WMI COM object, please check manually."
}
else {
    $launchWmiPermission = (([wmiclass]"Win32_SecurityDescriptorHelper").BinarySDToSDDL($comWmiObj.LaunchPermission)).SDDL

    $defaultWmiPermissions = @(
        @{
            name   = 'Administrators'
            short  = 'BA'
            sid    = 'S-1-5-32-544'
            launch = 'A;;CCDCLCSWRP;;;'
        }
        @{
            name   = 'Authenticated Users'
            short  = 'AU'
            sid    = 'S-1-5-11'
            launch = 'A;;CCDCSWRP;;;'
        }
    )

    foreach ($permission in $defaultWmiPermissions.GetEnumerator()) {
        if ($launchWmiPermission.Contains($permission.launch + $permission.short) -or $launchWmiPermission.Contains($permission.launch + $permission.sid)) {
            Write-LogMessage -Type Pass "The '$($permission.name)' group is present with default permissions."
        }
        else {
            Write-LogMessage -Type Error "The '$($permission.name)' group is NOT present with default permissions, please verify."
        }
    }
}

# Check event logs for known WMI events in the last 30 days
$cutoffDate = (Get-Date).AddDays(-30)
$wmiProvEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Application'
    ID        = 5612
    StartTime = $cutoffDate
} -ErrorAction SilentlyContinue
if ($wmiProvEvents) {
    Write-LogMessage -Type Warning "Detected $($wmiProvEvents.Count) events with ID 5612 detected in the Application event log in the last 30 days. This means that WmiPrvSE processes are exceeding some quota(s), please check."

    # Print the most recent 5 of them
    Write-LogMessage "Here are the most recent ones:"
    foreach ($event in ($wmiProvEvents | Select-Object -First 5)) {
        Write-LogMessage "$($event.TimeCreated) - $($event.Message)"
    }
}
else {
    Write-LogMessage -Type Pass "Did not detect any WMI Provider Host quota violation events in the Application log."
}


# Check for Corrupted.rec file
$corruptionSign = Get-ItemProperty "$env:SystemRoot\System32\wbem\repository\Corrupted.rec" -ErrorAction SilentlyContinue
if ($corruptionSign) {
    Write-LogMessage -Type Warning "Found 'Corrupted.rec' file. This means that the WMI repository could have been corrupted at some point & was restored/reset @ '$($corruptionSign.CreationTimeUtc)'."
    
    # check SCCM client auto remediation setting
    $ccmEval = Get-ItemProperty -Path "HKLM:\Software\Microsoft\CCM\CcmEval" -ErrorAction SilentlyContinue
    if ($ccmEval) {
        if ($ccmEval.NotifyOnly -eq 'TRUE') {
            Write-LogMessage -Type Pass "SCCM client automatic remediation is turned OFF. This should prevent it from automatically resetting the WMI repository."
        }
        else {
            Write-LogMessage -Type Warning "SCCM client automatic remediation is turned ON. This could be an explanation for the repository restore/reset. You can turn this OFF & see if the problem persists, check out this page `nhttps://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/configure-client-status#automatic-remediation-exclusion"
        }
    }
}
else {
    Write-LogMessage -Type Pass "Did not find a 'Corrupted.rec' file. This means that the WMI repository is probably healthy & was not restored/reset recently."
}

# Check repository file size
$repoFile = Get-ItemProperty "$env:SystemRoot\System32\wbem\repository\OBJECTS.DATA" -ErrorAction SilentlyContinue
if ($repoFile) {
    $size = $repoFile.Length / 1024 / 1024
    if ($size -lt 500) {
        Write-LogMessage -Type Pass "The WMI repository file is smaller than 500 MB ($size MB). This seems healthy."
    }
    else {
        if ($size -gt 1000) {
            Write-LogMessage -Type Error "The WMI repository file is larger than 1 GB ($size MB). This may cause issues like slow boot/logon."
        }
        else {
            Write-LogMessage -Type Warning "The WMI repository file is larger than 500 MB ($size MB). This may be a sign of repository bloating."
        }

        # check for RSOP logging reg key
        $rsopLogging = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue).RSoPLogging
        if ($rsopLogging -and $rsopLogging -eq 0) {
            Write-LogMessage -Type Pass "RSOP logging seems to be turned off, this is probably not why the repository is bloated."
        }
        else {
            Write-LogMessage -Type Warning "RSOP logging is turned on and this may be why the repository is so big. You can turn off RSOP logging via policy or registry:`nhttps://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.GroupPolicy::RSoPLogging"
        }
    }
}
else {
    Write-LogMessage -Type Warning "Could not get information about the WMI repository file."
}


Write-LogMessage "-------------------------"
Write-LogMessage "Checking domain / workgroup settings..."

# Check if machine is part of a domain or not
if ((Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain) {
    Write-LogMessage "The machine is part of a domain."

    # Check SPNs
    $search = New-Object DirectoryServices.DirectorySearcher([ADSI]"GC://$env:USERDNSDOMAIN") # The SPN is searched in the forest connecting to a Global catalog
    $SPN = "HTTP/" + $env:COMPUTERNAME
    Write-LogMessage ("Searching for the SPN $SPN")
    $search.filter = "(servicePrincipalName=$SPN)"
    $results = $search.Findall()
    if ($results.count -gt 0) {
        foreach ($result in $results) {
            Write-LogMessage "The SPN HTTP/$env:COMPUTERNAME is registered for DNS name = $($result.properties.dnshostname), DN = $($result.properties.distinguishedname), Category = $($result.properties.objectcategory)"
            if ($result.properties.objectcategory[0].Contains("Computer")) {
                if (-not $result.properties.dnshostname[0].Contains($env:COMPUTERNAME)) {
                    Write-LogMessage -Type Error "The SPN $SPN is registered for different DNS host name: $($result.properties.dnshostname[0])"
                }
                else {
                    Write-LogMessage -Type Pass "The SPN $SPN seems to be correctly registered to the computer account."
                }
            }
            else {
                Write-LogMessage -Type Error "The SPN $SPN is NOT registered for a computer account."
            }
        }
        if ($results.count -gt 1) {
            Write-LogMessage -Type Error "The SPN $SPN is duplicate."
        }
    }
    else {
        Write-LogMessage -Type Pass "The SPN $SPN was not found. That's ok, the SPN HOST/$env:COMPUTERNAME will be used."
    }

    
    # TODO - more checks for domain joined machines


}
else {
    Write-LogMessage -Type Warning "The machine is not joined to a domain."


    # TODO - more checks for non-domain joined (WORKGROUP) machines

}



Write-LogMessage "-------------------------"
Write-LogMessage "Checking networking settings..."

# check firewall remote administration exception policy
$admException = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\RemoteAdminSettings" -ErrorAction SilentlyContinue).Enabled
if (([string]::IsNullOrEmpty($admException)) -or ($admException -eq 0)) {
    Write-LogMessage -Type Pass "The RemoteAdministrationException policy is not configured or disabled. That is ok."
}
elseif ($admException -eq 1) {
    Write-LogMessage -Type Warning "The RemoteAdministrationException policy is turned on."
    $admExceptionList = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\RemoteAdminSettings" -ErrorAction SilentlyContinue).RemoteAddresses
    if ($admExceptionList) {
        Write-LogMessage -Type Warning "These are the addresses that are allowed through: $($admExceptionList)"
    }
}


# check default Firewall rules for WMI 
$fwRules = Show-NetFirewallRule -PolicyStore ActiveStore | Where-Object { ($_.DisplayGroup -like '*WMI*') -and ($_.Direction -eq 'Inbound') }
if ($fwRules) {
    foreach ($rule in $fwRules) {
        if ($rule.Enabled -eq 'True') {
            Write-LogMessage -Type Pass "Firewall rule '$($rule.DisplayName) - Profile: $($rule.Profile)' is enabled."
        }
        else {
            Write-LogMessage -Type Warning "Firewall rule '$($rule.DisplayName) - Profile: $($rule.Profile)' is not enabled."
        }
    }
}
else {
    Write-LogMessage -Type Error "Could not find any relevant Firewall rules, please look into this, as it is not normal!"
}


# Check HTTP regkey
$HttpParam = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -ErrorAction SilentlyContinue
if ($HttpParam -and ($HttpParam.MaxFieldLength -gt 0) -and ($HttpParam.MaxRequestBytes -gt 0)) {
    Write-LogMessage "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\MaxFieldLength = $($HttpParam.MaxFieldLength)"
    Write-LogMessage "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\MaxRequestBytes = $($HttpParam.MaxRequestBytes)"
}
else {
    Write-LogMessage -Type Warning "MaxFieldLength and/or MaxRequestBytes are not defined in HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters. This may cause the requests to fail with error 400 in complex AD environemnts. See KB 820129."
}


# Check IP listen filtering
$iplisten = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -ErrorAction SilentlyContinue).ListenOnlyList
if ($iplisten) {
    Write-LogMessage -Type Warning "The IPLISTEN list is not empty, the listed addresses are $(foreach ($ip in $iplisten) {$ip.ToString() +' |'})."
}
else {
    Write-LogMessage -Type Pass "The IPLISTEN list is empty. That's ok: we should listen on all IP addresses by default."
}


# Check winhttp proxy
$binval = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -ErrorAction SilentlyContinue).WinHttPSettings            
$proxylength = $binval[12]            
if ($proxylength -gt 0) {
    $proxy = -join ($binval[(12 + 3 + 1)..(12 + 3 + 1 + $proxylength - 1)] | ForEach-Object { ([char]$_) })            
    Write-LogMessage -Type Warning "A NETSH WINHTTP proxy is configured: $($proxy)"
    $bypasslength = $binval[(12 + 3 + 1 + $proxylength)]            
    if ($bypasslength -gt 0) {            
        $bypasslist = -join ($binval[(12 + 3 + 1 + $proxylength + 3 + 1)..(12 + 3 + 1 + $proxylength + 3 + 1 + $bypasslength)] | ForEach-Object { ([char]$_) })            
        Write-LogMessage -Type Warning "Bypass list: $($bypasslist)"
    }
    else {            
        Write-LogMessage -Type Warning "No bypass list is configured"
    }            
    Write-LogMessage -Type Warning "Remote WMI over DCOM does not work very well through proxies, make sure that the target machine is in the bypass list or remove the proxy"
}
else {
    Write-LogMessage -Type Pass "No NETSH WINHTTP proxy is configured"
}


# Check HTTPERR buildup
$dir = $env:windir + "\system32\logfiles\HTTPERR"
if (Test-Path -path $dir) {
    $httperrfiles = Get-ChildItem -path ($dir)
    $msg = "There are $($httperrfiles.Count) files in the folder $dir"
    if ($httperrfiles.Count -gt 100) {
        Write-LogMessage -Type Warning $msg
    }
    else {
        Write-LogMessage $msg
    }
    $size = 0 
    foreach ($file in $httperrfiles) {
        $size += $file.Length
    }
    $size = [System.Math]::Ceiling($size / 1024 / 1024) # Convert to MB
    $msg = "The folder $dir is using $($size.ToString()) MB of disk space."
    if ($size -gt 100) {
        Write-LogMessage -Type Warning $msg
    }
    else {
        Write-LogMessage $msg
    }
}