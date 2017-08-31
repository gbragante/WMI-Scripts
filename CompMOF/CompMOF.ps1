$version = "CompMOF (20170831)"
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

$resName = "CompMOF-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)
$resDir = $Root + "\" + $resName
$outfile = $resDir + "\script-output.txt"
$errfile = $resDir + "\script-errors.txt"
$RdrOut =  " >>""" + $outfile + """"
$RdrErr =  " 2>>""" + $errfile + """"

New-Item -itemtype directory -path $resDir | Out-Null

Write-Log $version

New-PSDrive -PSProvider registry -Root HKEY_LOCAL_MACHINE -Name HKLM -ErrorAction SilentlyContinue | Out-Null
$mof = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM")).'Autorecover MOFs'

if ($mof.length -eq 0) {
  Write-Log ("The registry key ""HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM\Autorecover MOFs"" is missing or empty")
  exit
}

$mof | Out-File ($resDir + "\Autorecover MOFs.txt")

foreach ($line in $mof) {
  if ($line.ToLower().contains("uninstall")) {
    Write-Log ("Skipping " + $line) 
  } else {
    $line = $line.Replace("%windir%", $env:windir) 
    $line = $line.Replace("%ProgramFiles%", $env:ProgramFiles) 
    if ($line -gt "") {
      if (Test-path $line) {
        Write-Log ("Compiling " + $line)
        $cmd = "mofcomp """ + $line + """"+ $RdrErr
        Write-Log $cmd
        Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append
      } else {
        Write-Log ("Missing file " + $line)
      }
    }
  }
}
