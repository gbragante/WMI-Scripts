# WMI-Report (20170313)
# by Gianni Bragante gbrag@microsoft.com

Function Get-WMINamespace($ns) {
  Write-Host $ns
  Get-WMIProviders $ns
  Get-Classes $ns
  Get-WmiObject -namespace $ns -class "__Namespace" | sort-object Name  |
  foreach {
    if ((($_.name.Length -le 2) -or ($_.name.Substring(0,3).ToLower() -ne "ms_")) -and (-not($_.name -match "LDAP"))) {
      Get-WMINamespace ($ns + "\" + $_.name)
    }
  }
}

Function Get-WMIProviders ($ns) {
  Get-WmiObject -NameSpace $ns -Class __Win32Provider | sort-object Name  |
  foreach {
    Get-ProvDetails $ns $_.name $_.CLSID $_.HostingModel
  }
}

Function Get-Classes ($ns) {
  Get-WmiObject -Namespace $ns -Query "select * from meta_class" | sort-object Name  |
  foreach {
    $dynamic = $_.Qualifiers["dynamic"].Value
    $static = $_.Qualifiers["static"].Value

    if( $abstract -eq $true  -or $dynamic -eq $true ) {
      if ($dynamic -eq $true) { # Dynamic class
        $row = $tbClass.NewRow()
        $row.NameSpace = $ns
        $row.Name = $_.name
        $row.Provider = $_.qualifiers["Provider"].value
        $tbClass.Rows.Add($row)
      }
    } else {
      if (-not $_.name.Startswith("__")) {
        if ($static -eq $true) { # Static class = Repository
          $row = $tbRep.NewRow()
          $row.NameSpace = $ns
          $row.Name = $_.name
          $row.Inst = $_.GetInstances().Count
          $tbRep.Rows.Add($row)
        } else {
          $inst = $_.GetInstances().Count # Class with instances, repository as well
          if ($inst  -gt 0) {
            $row = $tbRep.NewRow()
            $row.NameSpace = $ns
            $row.Name = $_.name
            $row.Inst = $Inst
            $tbRep.Rows.Add($row)
          }
        }
      }
    }
  }
}

Function Get-ProvDetails($ns, $name, $clsid, $HostingModel) {
  $row = $tbProv.NewRow()
  $row.NameSpace = $ns
  $row.Name = $name
  $row.HostingModel = $HostingModel
  $row.CLSID= $clsid
  $dll = " "
  if ($clsid -ne $null) {
    if (-not ($HostingModel -match "decoupled") -and ($HostingModel -ne "SelfHost")) {
      $name = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKCR:\CLSID\" + $clsid)).'(default)'
      if ($name.length -gt 0 ) { 
        # Write-Log ("  " + (get-itemproperty -literalpath ("HKCR:\CLSID\" + $clsid)).'(default)')
      }
      $dll = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKCR:\CLSID\" + $clsid + "\InprocServer32")).'(default)'
      if ($dll) {
        $row.dtDLL = (Get-Item $dll).CreationTime
        $row.verDLL = (Get-Item $dll).VersionInfo.FileVersion
      }
      $row.ThreadingModel = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKCR:\CLSID\" + $clsid + "\InprocServer32")).'ThreadingModel'
    }
  }
  $row.DLL= $dll
  $tbProv.Rows.Add($row)
}

function Write-Log($line) {
  Write-Host $line
  Out-File -Filepath $resDir"\WMI-Report.txt" -encoding default -InputObject $line -Append
}

$Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path

$resName = "WMI-Report-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)
$resDir = $Root + "\" + $resName

New-Item -itemtype directory -path $resDir | Out-Null

New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR | Out-Null

$tbProv = New-Object system.Data.DataTable “WmiProv”
$col = New-Object system.Data.DataColumn NameSpace,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn Name,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn HostingModel,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn ThreadingModel,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn DLL,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn dtDLL,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn verDLL,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn CLSID,([string])
$tbProv.Columns.Add($col)

$tbClass = New-Object system.Data.DataTable “Classes”
$col = New-Object system.Data.DataColumn NameSpace,([string])
$tbClass.Columns.Add($col)
$col = New-Object system.Data.DataColumn Name,([string])
$tbClass.Columns.Add($col)
$col = New-Object system.Data.DataColumn Provider,([string])
$tbClass.Columns.Add($col)

$tbRep = New-Object system.Data.DataTable “Repository”
$col = New-Object system.Data.DataColumn NameSpace,([string])
$tbRep.Columns.Add($col)
$col = New-Object system.Data.DataColumn Name,([string])
$tbRep.Columns.Add($col)
$col = New-Object system.Data.DataColumn Inst,([string])
$tbRep.Columns.Add($col)

Get-WMINamespace "Root"

Write-Host "Writing Providers.csv"
$tbProv | Export-Csv $resDir"\Providers.csv" -noType
Write-Host "Writing Classes.csv"
$tbClass | Export-Csv $resDir"\Classes.csv" -noType
Write-Host "Writing Repository.csv"
$tbRep | Export-Csv $resDir"\Repository.csv" -noType
