Function Get-DomainGroupNameBySid {
  param ($SIDString)
  $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
  $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://<SID=$SIDString>")

  return $directoryEntry.Name
}

Function Get-LocalGroupNameBySid {
  param ($SIDString)

  $group = New-Object System.Security.Principal.SecurityIdentifier($SIDString)

  if ($group -ne $null) {
    return $group.Translate([System.Security.Principal.NTAccount]).Value -replace '.+\\'
  } else {
    return $null
  }
}

Function Get-LocalGroupMembers {
  param ($name)
  $ADSI = [ADSI]"WinNT://./$name"
  $ADSI.Invoke("Members") | foreach {$_.GetType().InvokeMember("ADsPath", 'GetProperty', $null, $_, $null)}
  return $members
}


$name = Get-LocalGroupNameBySid "S-1-5-32-580"
$list = Get-LocalGroupMembers $name

$list
$name
