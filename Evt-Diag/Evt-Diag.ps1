$version = "Evt-Diag (20200102)"
# by Gianni Bragante - gbrag@microsoft.com

Function Write-Log {
  param( [string] $msg )
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg
  $msg | Out-File -FilePath $outfile -Append
}

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

$Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path

$resName = "Evt-Diag-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)
$resDir = $Root + "\" + $resName
$outfile = $resDir + "\script-output.txt"
$errfile = $resDir + "\script-errors.txt"
$RdrOut =  " >>""" + $outfile + """"
$RdrErr =  " 2>>""" + $errfile + """"

New-Item -itemtype directory -path $resDir | Out-Null

Write-Log $version

$loggersRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger"
$pubRoot = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers"

Write-Log ("loggersRoot " + $loggersRoot)
Write-Log ("pubRoot " + $pubRoot)

$loggers = Get-ChildItem -Path $loggersRoot
foreach ($logger in $loggers) {
  Write-Log ("[INFO] Inspecting logger " + $logger.PSChildName)
  $pubs = Get-ChildItem -Path ($logger.Name).replace("HKEY_LOCAL_MACHINE\","HKLM:\")
  foreach ($pub in $pubs) {
    $pubProp = ($pub | Get-ItemProperty)
    Write-Log ("[INFO]   Inspecting provider " + $pub.PSChildName + " Enabled = " + $pubProp.Enabled + " Status = " + $pubProp.Status)
    $pubInfo = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ($pubRoot + "\" + $pub.PSChildName))
    if ($pubInfo) {
      Write-Log ("[INFO]     " + $pubInfo.'(default)')
      if (Test-Path -Path $pubInfo.ResourceFileName) {
        $dll = get-item ($pubInfo.ResourceFileName)
        Write-Log ("[INFO]     Resource file found " + $pubInfo.ResourceFileName + " Version " + $dll.VersionInfo.FileVersion + " " + $dll.CreationTime)
      } else {
        Write-Log ("[ERROR]    Resource file NOT found " + $pubInfo.ResourceFileName)
      }
      if (Test-Path -Path $pubInfo.MessageFileName) {
        Write-Log ("[INFO]     Message file found " + $pubInfo.MessageFileName)
      } else {
        Write-Log ("[ERROR]    Message file NOT found " + $pubInfo.MessageFileName)
      }
    } else {
      Write-Log ("[ERROR]    Publisher not found " + $pub.PSChildName)
    }
  }
}