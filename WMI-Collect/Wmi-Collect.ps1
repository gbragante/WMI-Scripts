$version = "WMI-Collect (20180219)"
# by Gianni Bragante - gbrag@microsoft.com

Function Write-Log {
  param( [string] $msg )
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg
  $msg | Out-File -FilePath $outfile -Append
}

Function ExecQuery {
  param(
    [string] $NameSpace,
    [string] $Query
  )
  Write-Log ("Executing query " + $Query)
  if ($PSVersionTable.psversion.ToString() -ge "3.0") {
    $ret = Get-CimInstance -Namespace $NameSpace -Query $Query -ErrorAction Continue 2>>$errfile
  } else {
    $ret = Get-WmiObject -Namespace $NameSpace -Query $Query -ErrorAction Continue 2>>$errfile
  }
  Write-Log (($ret | measure).count.ToString() + " results")
  return $ret
}

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

$Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path

$resName = "WMI-Results-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)
$resDir = $Root + "\" + $resName
$outfile = $resDir + "\script-output.txt"
$errfile = $resDir + "\script-errors.txt"

if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
  $procdump = "procdump64.exe"
} else {
  $procdump = "procdump.exe"
}
if (-not (Test-Path ($root + "\" + $procdump))) {
  $confirm = Read-Host ("The file " + $root + "\" + $procdump + " does not exist, the process dumps cannot be collected.`r`nDo you want to continue ? [Y / N]")
  if ($confirm.ToLower() -ne "y") {exit}
}

New-Item -itemtype directory -path $resDir | Out-Null

Write-Log $version
Write-Log "Collecting dump of the svchost process hosting the WinMgmt service"
$cmd = "&""" + $Root + "\" +$procdump + """ -accepteula -ma WinMgmt """ + $resDir + "\Svchost.exe-WinMgmt.dmp"" >>""" + $outfile + """ 2>>""" + $errfile + """"
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Collecing the dumps of WMIPrvSE.exe processes"
$list = get-process -Name "WmiPrvSe" -ErrorAction Continue 2>>$errfile
if (($list | measure).count -gt 0) {
  foreach ($proc in $list)
  {
    Write-Log ("Found WMIPrvSE.exe with PID " + $proc.Id)
    $cmd = "&""" + $Root + "\" +$procdump + """ -accepteula -ma " + $proc.Id + " """+ $resDir + "\WMIPrvSE.exe_"+ $proc.id + ".dmp"" >>""" + $outfile + """ 2>>""" + $errfile + """"
    Write-Log $cmd
    Invoke-Expression $cmd
  }
} else {
  Write-Log "No WMIPrvSE.exe processes found"
}

Write-Log "Collecing the dumps of decoupled WMI providers"
$list = Get-Process
if (($list | measure).count -gt 0) {
  foreach ($proc in $list)
  {
    $prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "wmidcprv.dll"} 
    if (($prov | measure).count -gt 0) {
      Write-Log ("Found " + $proc.Name + "(" + $proc.id + ")")
      $cmd = "&""" + $Root + "\" +$procdump + """ -accepteula -ma " + $proc.Id + " """+ $resDir + "\"+ $proc.name + ".exe_"+ $proc.id + ".dmp"" >>""" + $outfile + """ 2>>""" + $errfile + """"
      Write-Log $cmd
      Invoke-Expression $cmd
    }
  }
}

Write-Log "Collecting dump of the WmiApSrv.exe process"
$cmd = "&""" + $Root + "\" +$procdump + """ -accepteula -ma WmiApSrv.exe """ + $resDir + "\WmiApSrv.dmp"" >>""" + $outfile + """ 2>>""" + $errfile + """"
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Collecting Autorecover MOFs content"
$mof = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM")).'Autorecover MOFs'
if ($mof.length -eq 0) {
  Write-Log ("The registry key ""HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM\Autorecover MOFs"" is missing or empty")
  exit
}
$mof | Out-File ($resDir + "\Autorecover MOFs.txt")

Write-Log "Listing WBEM folder"
Get-ChildItem $env:windir\system32\wbem -Recurse | Out-File $resDir\wbem.txt

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole """+ $resDir + "\Ole.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $errfile + """"
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Wbem"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Wbem """+ $resDir + "\wbem.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $errfile + """"
Invoke-Expression $cmd

Write-Log "Exporting Application log"
$cmd = "wevtutil epl Application """+ $resDir + "\" + $env:computername + "-Application.evtx"" >>""" + $outfile + """ 2>>""" + $errfile + """"
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting System log"
$cmd = "wevtutil epl System """+ $resDir + "\" + $env:computername + "-System.evtx"" >>""" + $outfile + """ 2>>""" + $errfile + """"
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting DSC log"
$cmd = "wevtutil epl Microsoft-Windows-WMI-Activity/Operational """+ $resDir + "\" + $env:computername + "-WMI-Activity.evtx"" >>""" + $outfile + """ 2>>""" + $errfile + """"
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting DSC log"
$cmd = "wevtutil epl Microsoft-Windows-DSC/Operational """+ $resDir + "\" + $env:computername + "-DSC.evtx"" >>""" + $outfile + """ 2>>""" + $errfile + """"
Write-Log $cmd
Invoke-Expression $cmd

if ($PSVersionTable.psversion.ToString() -ge "3.0") {
  $actLog = Get-WinEvent -logname Microsoft-Windows-WMI-Activity/Operational -Oldest -ErrorAction Continue 2>>$errfile
  if (($actLog  | measure).count -gt 0) {
    Write-Log "Exporting WMI-Activity log"
    $actLog | Out-String -width 1000 | Out-File -FilePath ($resDir + "\WMI-Activity.txt")
  }
}

Write-Log "Exporting netstat output"
$cmd = "netstat -anob >""" + $resDir + "\netstat.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Exporting ipconfig /all output"
$cmd = "ipconfig /all >""" + $resDir + "\ipconfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Exporting service configuration"
$cmd = "sc.exe queryex winmgmt >>""" + $resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

$cmd = "sc.exe qc winmgmt >>""" + $resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

$cmd = "sc.exe enumdepend winmgmt 3000 >>""" + $resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

$cmd = "sc.exe sdshow winmgmt >>""" + $resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Collecting details about running processes"
$proc = ExecQuery -Namespace "root\cimv2" -Query "select CreationDate, ProcessId, ParentProcessId, WorkingSetSize, UserModeTime, KernelModeTime, ThreadCount, HandleCount, CommandLine from Win32_Process"
if ($PSVersionTable.psversion.ToString() -ge "3.0") {
  $StartTime= @{e={$_.CreationDate.ToString("yyyyMMdd HH:mm:ss")};n="Start time"}
} else {
  $StartTime= @{n='StartTime';e={$_.ConvertToDateTime($_.CreationDate)}}
}

if ($proc) {
  $proc | Sort-Object Name |
  Format-Table -AutoSize -property @{e={$_.ProcessId};Label="PID"}, @{e={$_.ParentProcessId};n="Parent"}, Name,
  @{N="WorkingSet";E={"{0:N0}" -f ($_.WorkingSetSize/1kb)};a="right"},
  @{e={[DateTime]::FromFileTimeUtc($_.UserModeTime).ToString("HH:mm:ss")};n="UserTime"}, @{e={[DateTime]::FromFileTimeUtc($_.KernelModeTime).ToString("HH:mm:ss")};n="KernelTime"},
  @{N="Threads";E={$_.ThreadCount}}, @{N="Handles";E={($_.HandleCount)}}, $StartTime, CommandLine |
  Out-String -Width 500 | Out-File -FilePath ($resDir + "\processes.txt")

  Write-Log "Collecting services details"
  $svc = ExecQuery -NameSpace "root\cimv2" -Query "select  ProcessId, DisplayName, StartMode,State, Name, PathName, StartName from Win32_Service"

  if ($svc) {
    $svc | Sort-Object DisplayName | Format-Table -AutoSize -Property ProcessId, DisplayName, StartMode,State, Name, PathName, StartName |
    Out-String -Width 400 | Out-File -FilePath ($resDir + "\services.txt")
  }

  Write-Log "Collecting system information"
  $pad = 27
  $OS = ExecQuery -Namespace "root\cimv2" -Query "select Caption, CSName, OSArchitecture, BuildNumber, InstallDate, LastBootUpTime, LocalDateTime, TotalVisibleMemorySize, FreePhysicalMemory, SizeStoredInPagingFiles, FreeSpaceInPagingFiles from Win32_OperatingSystem"
  $CS = ExecQuery -Namespace "root\cimv2" -Query "select Model, Manufacturer, SystemType, NumberOfProcessors, NumberOfLogicalProcessors, TotalPhysicalMemory, DNSHostName, Domain, DomainRole from Win32_ComputerSystem"
  $BIOS = ExecQuery -Namespace "root\cimv2" -query "select BIOSVersion, Manufacturer, ReleaseDate, SMBIOSBIOSVersion from Win32_BIOS"
  $TZ = ExecQuery -Namespace "root\cimv2" -Query "select Description from Win32_TimeZone"
  $PR = ExecQuery -Namespace "root\cimv2" -Query "select Name, Caption from Win32_Processor"

  "Computer name".PadRight($pad) + " : " + $OS.CSName | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Model".PadRight($pad) + " : " + $CS.Model | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Manufacturer".PadRight($pad) + " : " + $CS.Manufacturer | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "BIOS Version".PadRight($pad) + " : " + $BIOS.BIOSVersion | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "BIOS Manufacturer".PadRight($pad) + " : " + $BIOS.Manufacturer | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "BIOS Release date".PadRight($pad) + " : " + $BIOS.ReleaseDate | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "SMBIOS Version".PadRight($pad) + " : " + $BIOS.SMBIOSBIOSVersion | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "SystemType".PadRight($pad) + " : " + $CS.SystemType | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Processor".PadRight($pad) + " : " + $PR.Name + " / " + $PR.Caption | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Processors physical/logical".PadRight($pad) + " : " + $CS.NumberOfProcessors + " / " + $CS.NumberOfLogicalProcessors | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Memory physical/visible".PadRight($pad) + " : " + ("{0:N0}" -f ($CS.TotalPhysicalMemory/1mb)) + " MB / " + ("{0:N0}" -f ($OS.TotalVisibleMemorySize/1kb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Free physical memory".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.FreePhysicalMemory/1kb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Paging files size / free".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.SizeStoredInPagingFiles/1kb)) + " MB / " + ("{0:N0}" -f ($OS.FreeSpaceInPagingFiles/1kb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Operating System".PadRight($pad) + " : " + $OS.Caption + " " + $OS.OSArchitecture | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Build Number".PadRight($pad) + " : " + $OS.BuildNumber | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Time zone".PadRight($pad) + " : " + $TZ.Description | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Install date".PadRight($pad) + " : " + $OS.InstallDate | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Last boot time".PadRight($pad) + " : " + $OS.LastBootUpTime | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Local time".PadRight($pad) + " : " + $OS.LocalDateTime | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "DNS Hostname".PadRight($pad) + " : " + $CS.DNSHostName | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Domain".PadRight($pad) + " : " + $CS.Domain | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  $roles = "Standalone Workstation", "Member Workstation", "Standalone Server", "Member Server", "Backup Domain Controller", "Primary Domain Controller"
  "Domain role".PadRight($pad) + " : " + $roles[$CS.DomainRole] | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
} else {
  $proc = Get-Process | Where-Object {$_.Name -ne "Idle"}
  $proc | Format-Table -AutoSize -property id, name, @{N="WorkingSet";E={"{0:N0}" -f ($_.workingset/1kb)};a="right"},
  @{N="VM Size";E={"{0:N0}" -f ($_.VirtualMemorySize/1kb)};a="right"},
  @{N="Proc time";E={($_.TotalProcessorTime.ToString().substring(0,8))}}, @{N="Threads";E={$_.threads.count}},
  @{N="Handles";E={($_.HandleCount)}}, StartTime, Path | 
  Out-String -Width 300 | Out-File -FilePath ($resDir + "\processes.txt")
}

Write-Log "Collecting the list of installed hotfixes"
Get-HotFix -ErrorAction SilentlyContinue 2>>$errfile | Sort-Object -Property InstalledOn | Out-File $resDir\hotfixes.txt

Write-Log "Collecting details of provider hosts"
New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR -ErrorAction SilentlyContinue | Out-Null

"Coupled providers (WMIPrvSE.exe processes)" | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append
"" | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append

$totMem = 0

$prov = ExecQuery -NameSpace "root\cimv2" -Query "select HostProcessIdentifier, Provider, Namespace, User from MSFT_Providers"
if ($prov) {
  $proc = ExecQuery -NameSpace "root\cimv2" -Query "select ProcessId, HandleCount, ThreadCount, PrivatePageCount, CreationDate, KernelModeTime, UserModeTime from Win32_Process where name = 'wmiprvse.exe'"
  foreach ($prv in $proc) {
    $provhost = $prov | Where-Object {$_.HostProcessIdentifier -eq $prv.ProcessId}

    if (($provhost | measure).count -gt 0) {
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

      "PID" + " " + $prv.ProcessId + " (" + [String]::Format("{0:x}", $prv.ProcessId) + ") Handles:" + $prv.HandleCount +" Threads:" + $prv.ThreadCount + " Private KB:" + ($prv.PrivatePageCount/1kb) + " KernelTime:" + $kh + " UserTime:" + $uh + " Uptime:" + $uptime | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append
      $totMem = $totMem + $prv.PrivatePageCount
    } else {
      Write-Log ("No provider found for the WMIPrvSE process with PID " +  $prv.ProcessId)
    }

    foreach ($provname in $provhost) {
      $provdet = ExecQuery -NameSpace $provname.Namespace -Query ("select * from __Win32Provider where Name = """ + $provname.Provider + """")
      $hm = $provdet.hostingmodel
      $clsid = $provdet.CLSID
      $dll = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKCR:\CLSID\" + $clsid + "\InprocServer32")).'(default)' 2>>$errfile
      $dll = $dll.Replace("""","")
      $file = Get-Item ($dll)
      $dtDLL = $file.CreationTime
      $verDLL = $file.VersionInfo.FileVersion

      $provname.Namespace + " " + $provname.Provider + " " + $dll + " " + $hm + " " + $provname.user + " " + $dtDLL + " " + $verDLL 2>>$errfile | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append
    }
    " " | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append
  }
}
"Total memory used by coupled providers: " + ($totMem/1kb) + " KB" | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append
" " | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append

# Details of decoupled providers
$list = Get-Process
foreach ($proc in $list) {
  $prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "wmidcprv.dll"} 
  if (($prov | measure).count -gt 0) {
    if (-not $hdr) {
      "Decoupled providers" | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append
      " " | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append
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

    ($prc.ExecutablePath + $svc) | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append
    "PID " + $prc.ProcessId  + " (" + [String]::Format("{0:x}", $prc.ProcessId) + ")  Handles: " + $prc.HandleCount + " Threads: " + $prc.ThreadCount + " Private KB: " + ($prc.PrivatePageCount/1kb) + " KernelTime:" + $kh + " UserTime:" + $uh + " Uptime:" + $uptime | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append

    $Keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Wbem\Transports\Decoupled\Client
    $Items = $Keys | Foreach-Object {Get-ItemProperty $_.PsPath }
    ForEach ($key in $Items) {
      if ($key.ProcessIdentifier -eq $prc.ProcessId) {
        ($key.Scope + " " + $key.Provider) | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append
      }
    }
    " " | Out-File -FilePath ($resDir + "\ProviderHosts.txt") -Append
  }
}

Write-Log "Collecting quota details"
$quota = ExecQuery -Namespace "Root" -Query "select * from __ProviderHostQuotaConfiguration"
if ($quota) {
  ("ThreadsPerHost : " + $quota.ThreadsPerHost + "`r`n") + `
  ("HandlesPerHost : " + $quota.HandlesPerHost + "`r`n") + `
  ("ProcessLimitAllHosts : " + $quota.ProcessLimitAllHosts + "`r`n") + `
  ("MemoryPerHost : " + $quota.MemoryPerHost + "`r`n") + `
  ("MemoryAllHosts : " + $quota.MemoryAllHosts + "`r`n") | Out-File -FilePath ($resDir + "\ProviderHostQuotaConfiguration.txt") -Append
}
