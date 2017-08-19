# FindClassDLL.ps1
# by Gianni Bragante gbrag@microsoft.com

param(
  [String]$NameSpace = "root\cimv2",
  [String]$ClassName
)

if([string]::IsNullOrEmpty($className)) {            
    Write-Host "Please specity a class name"            
    Exit
} 

New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR -ErrorAction SilentlyContinue | Out-Null

$cl="\\.\"+$NameSpace+":"+$className
$class = [WMICLASS]$cl


if (-not $class) {
  Write-Host "Cannot find class" $className
  exit
}

Write-host "Namespace :" $NameSpace
Write-Host "Class:" $className
Write-host "Description :" $class.Qualifiers["Description"].Value

$provname = $class.Qualifiers["Provider"].Value
$prov = Get-WmiObject -Namespace $NameSpace -Class __Win32Provider | Where-Object name -eq $provname

if (-not $provname) {
  write-host "Provider not found for this class"
  exit
}

Write-host "Provider :" $provname
Write-host "CLSID :" $prov.CLSID
Write-Host "HostingModel :" $prov.HostingModel
$DLLName = (get-itemproperty -literalpath ("HKCR:\CLSID\" + $prov.CLSID+ "\InprocServer32")).'(default)'

write-host
Write-host "DLL name :" $DLLname
Write-host "DLL date :" (Get-Item $DLLName).CreationTime
Write-host "DLL description :" (Get-Item $DLLName).VersionInfo.FileDescription
Write-host "You can try regsvr32 /s" $DLLname

$mof = "C:\Windows\System32\wbem\"+[io.path]::GetFileNameWithoutExtension($DLLname) +".mof"
$mofname = [io.path]::GetFileNameWithoutExtension($DLLname)
if ( Test-Path $mof) {
  write-host
  Write-host "MOF: " $mof
  Write-host "You can try mofcomp" $mofname".mof from C:\Windows\System32\wbem"
} else {
  Write-host "No matching MOF found"
}