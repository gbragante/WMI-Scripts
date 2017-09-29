# ListHosts.ps1 20170929
# by Gianni Bragante - gbrag@microsoft.com

Function ExecQuery {
  param(
    [string] $NameSpace,
    [string] $Query
  )
  if ($PSVersionTable.psversion.ToString() -ge "3.0") {
    $ret = Get-CimInstance -Namespace $NameSpace -Query $Query -ErrorAction Continue 2>>$errfile
  } else {
    $ret = Get-WmiObject -Namespace $NameSpace -Query $Query -ErrorAction Continue 2>>$errfile
  }
  return $ret
}

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR -ErrorAction SilentlyContinue | Out-Null
$prov = ExecQuery -NameSpace "root\cimv2" -Query "select HostProcessIdentifier, Provider, Namespace, User from MSFT_Providers"
if (!$prov) {
  Write-host "WMI is not functional"
  exit
}

Write-host "Coupled providers (WMIPrvSE.exe processes)"
Write-host ""

$proc = ExecQuery -NameSpace "root\cimv2" -Query "select ProcessId, HandleCount, ThreadCount, PrivatePageCount, CreationDate from Win32_Process where name = 'wmiprvse.exe'"
foreach ($prv in $proc) {
  $provhost = $prov | Where-Object {$_.HostProcessIdentifier -eq $prv.ProcessId}
  if ($PSVersionTable.psversion.ToString() -ge "3.0") {
    $ut= New-TimeSpan -Start $prv.CreationDate
  } else {
    $ut= New-TimeSpan -Start $prv.ConvertToDateTime($prv.CreationDate)
  }
  
  Write-Host "PID"$prv.ProcessId "Handles:"$prv.HandleCount "Threads:"$prv.ThreadCount "Private KB:"($prv.PrivatePageCount/1kb) "Uptime:"($ut.Days.ToString() + "d " + $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00"))
  foreach ($provname in $provhost) {
    $provdet = ExecQuery -NameSpace $provname.Namespace -Query ("select * from __Win32Provider where Name = """ + $provname.Provider + """")
    $hm = $provdet.hostingmodel
    $clsid = $provdet.CLSID
    $dll = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKCR:\CLSID\" + $clsid + "\InprocServer32")).'(default)'

    Write-Host $provname.Namespace $provname.Provider $dll $hm $provname.user 
  }
  Write-Host
}

$list = Get-Process
foreach ($proc in $list) {
  $prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "wmidcprv.dll"} 
  if (($prov | measure).count -gt 0) {
    if (-not $hdr) {
      Write-host "Decoupled providers"
      Write-host ""
      $hdr = $true
    }

    $prc = ExecQuery -Namespace "root\cimv2" -Query ("select ProcessId, CreationDate, HandleCount, ThreadCount, PrivatePageCount, ExecutablePath from Win32_Process where ProcessId = " +  $proc.id)
    if ($PSVersionTable.psversion.ToString() -ge "3.0") {
      $ut= New-TimeSpan -Start $prc.CreationDate
    } else {
      $ut= New-TimeSpan -Start $prc.ConvertToDateTime($prc.CreationDate)
    }

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

    Write-Host ($prc.ExecutablePath + $svc)
    Write-Host "PID"$prc.ProcessId "Handles:"$prc.HandleCount "Threads:"$prc.ThreadCount "Private KB:"($prc.PrivatePageCount/1kb) "Uptime:"($ut.Days.ToString() + "d " + $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00"))

    $Keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Wbem\Transports\Decoupled\Client
    $Items = $Keys | Foreach-Object {Get-ItemProperty $_.PsPath }
    ForEach ($key in $Items) {
      if ($key.ProcessIdentifier -eq $prc.ProcessId) {
        Write-Host ($key.Scope + " " + $key.Provider)
      }
    }
    Write-Host ""
  }
}

