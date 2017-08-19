# ListHosts.ps1 20170128
# by Gianni Bragante - gbrag@microsoft.com

New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR -ErrorAction SilentlyContinue | Out-Null
if ($PSVersionTable.psversion.ToString() -ge "3.0") {
  $prov = Get-CimInstance -Namespace "root\cimv2" -Class MSFT_Providers -ErrorAction SilentlyContinue
} else {
  $prov = Get-WmiObject -Namespace "root\cimv2" -Class MSFT_Providers -ErrorAction SilentlyContinue
}
if (!$prov) {
  Write-host "WMI is not functional"
  exit
}

if ($PSVersionTable.psversion.ToString() -ge "3.0") {
  $proc = Get-CimInstance -Query "select * from Win32_Process where name = 'wmiprvse.exe'" -ErrorAction SilentlyContinue
} else {
  $proc = Get-WmiObject -Query "select * from Win32_Process where name = 'wmiprvse.exe'" -ErrorAction SilentlyContinue
}
foreach ($prv in $proc) {
  $provhost = $prov | Where-Object {$_.HostProcessIdentifier -eq $prv.ProcessId}
  if ($PSVersionTable.psversion.ToString() -ge "3.0") {
    $ut= New-TimeSpan -Start $prv.CreationDate
  } else {
    $ut= New-TimeSpan -Start $prv.ConvertToDateTime($prv.CreationDate)
  }
  
  Write-Host "PID"$prv.ProcessId "Handles:"$prv.HandleCount "Threads:"$prv.ThreadCount "Private KB:"($prv.PrivatePageCount/1kb) "Uptime:"($ut.Days.ToString() + "d " + $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00"))
  foreach ($provname in $provhost) {
    if ($PSVersionTable.psversion.ToString() -ge "3.0") {
      $provdet = Get-CimInstance -Namespace $provname.Namespace -Class __Win32Provider | Where-Object {$_.Name -eq $provname.Provider}
      $hm = (Get-CimInstance -Namespace $provname.Namespace -Class __Win32Provider | where-object {$_.name -eq $provname.Provider}).hostingmodel
    } else {
      $provdet = Get-WmiObject -Namespace $provname.Namespace -Class __Win32Provider | Where-Object {$_.Name -eq $provname.Provider}
      $hm = (Get-WmiObject -Namespace $provname.Namespace -Class __Win32Provider | where-object {$_.name -eq $provname.Provider}).hostingmodel
    }

    $clsid = $provdet.CLSID
    $dll = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKCR:\CLSID\" + $clsid + "\InprocServer32")).'(default)'

    write-host $provname.Namespace $provname.Provider $dll $hm $provname.user 
  }
  Write-Host
}