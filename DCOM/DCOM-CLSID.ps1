param (
  [string] $ID = "{03E09F3B-DCE4-44FE-A9CF-82D050827E1C}"
)

$version = "DCOM-CLSID (20211231)"
# by Gianni Bragante - gbrag@microsoft.com

New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR -ErrorAction SilentlyContinue | Out-Null

if ($id) {
  $reg = Get-ItemProperty ("HKCR:\CLSID\" + $id) -ErrorAction SilentlyContinue
  if ($reg) {
    Write-Host ("HKCR:\CLSID\" + $id)
    Write-host ("CLSID : " + $id)
    Write-Host ("Name: " + $reg.'(default)')
    $reg = Get-ItemProperty ("HKCR:\CLSID\" + $id + "\LocalServer32") -ErrorAction SilentlyContinue
    if ($reg) {
      Write-Host ("Process: " + $reg.'(default)')
    }
    Write-Host
    exit
  }

  $reg = Get-ItemProperty ("HKCR:\AppID\" + $id) -ErrorAction SilentlyContinue
  if ($reg) {
    Write-host ("Application ID : " + $id)
    Write-Host ("Name: " + $reg.'(default)')
    if ($reg.LocalService) {
      Write-Host ("LocalService: " + $reg.LocalService)
    }
    Write-host
    exit
  }
}