# RPC-TraceParse - 20210329
# by Gianni Bragante - gbrag@microsoft.com

param (
  [string]$FileName = "C:\files\RPC-TraceParse\wmi-trace-gbrag-t470s-!FMT.txt"
)

Function LineParam {
  $npos=$line.IndexOf("::")
  $time = ($line.Substring($nPos + 2 , 25))
  $thread = $line.Substring(0,20).Replace(" ","")
  $npos = $thread.indexof("]")
  $thread = $thread.Substring($npos + 1, $thread.IndexOf("::") - $npos -1)
  $LinePid = [int32]("0x" + $thread.Substring(0,$thread.IndexOf(".")))
  $LineTid = [int32]("0x" + $thread.Substring($thread.IndexOf(".")+1))
  return @{ Time = $time; Thread = $thread; PID = $LinePid; TID = $LineTid }
}

Function DecodeIFUUID {
  param (
    [string]$GUID
  )
  $ret = $htGUID[$GUID]
  if ($ret) {
    return $ret
  } else {
    return "Unknown"
  }
}

Function FindSep {
  param( [string]$FindIn, [string]$Left,[string]$Right )

  if ($left -eq "") {
    $Start = 0
  } else {
    $Start = $FindIn.IndexOf($Left) 
    if ($Start -gt 0 ) {
      $Start = $Start + $Left.Length
    } else {
       return ""
    }
  }

  if ($Right -eq "") {
    $End = $FindIn.Substring($Start).Length
  } else {
    $End = $FindIn.Substring($Start).IndexOf($Right)
    if ($end -le 0) {
      return ""
    }
  }
  $Found = $FindIn.Substring($Start, $End)
  return $Found
}

$KFileName = ""
$fileobj = Get-Item $FileName
if ($fileobj.Basename.ToLower().Contains("wmi-trace")) {
  $KFileName = $fileobj.DirectoryName + "\" + $fileobj.Basename.ToLower().Replace("wmi-trace-","wmi-trace-kernel-") + ".txt"
}

if (-not (Test-Path ($FileName))) {
  Write-Host "WMI trace not found"
  exit
}

if ($KFileName) {
  if (Test-Path ($KFileName)) {
    $Kernel = $true
  } else {
    Write-Host "Kernel trace not found"
    $Kernel = $false
  }
}

$htGUID = @{ "{e60c73e6-88f9-11cf-9af1-0020af6e72f4}" = "ILocalObjectExporter"; 
             "{4f32adc8-6052-4a04-8701-293ccf2096f0}" = "sspirpc";
             "{8a7b5006-cc13-11db-9705-005056c00008}" = "??";
             "{00000136-0000-0000-c000-000000000046}" = "ISCMLocalActivator";
             "{00000132-0000-0000-c000-000000000046}" = "ILocalSystemActivator";
             "{00000001-0000-0000-c000-000000000046}" = "IClassFactory";
             "{00000134-0000-0000-c000-000000000046}" = "IRundown";
             "{af86e2e0-b12d-4c6a-9c5a-d7aa65101e90}" = "IInspectable"
            }

$tbEvt = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Time,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Side,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn PID,([int32]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn TID,([int32]); $tbEvt.Columns.Add($col)
if ($Kernel) {
  $col = New-Object system.Data.DataColumn Process,([string]); $tbEvt.Columns.Add($col)
}
$col = New-Object system.Data.DataColumn InterfaceUuid,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn InterfaceName,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn OpNum,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Protocol,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn NetworkAddress,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Endpoint,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn BindingOptions,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn AuthenticationLevel,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn AuthenticationService,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn ImpersonationLevel,([string]); $tbEvt.Columns.Add($col)

$dtInit = Get-Date

$sr = new-object System.io.streamreader(get-item $FileName)
$line = $sr.ReadLine()
while (-not $sr.EndOfStream) {
  $part = ""
  $part = $line

  $npos = $part.IndexOf("::")
  $time = ($part.Substring($nPos + 2 , 25))
  
  if ($part -match  "\[Debug \]") { 
    $LP = LineParam
    if ($part -match  "RPC call started") {
      Write-Host $part
      if ($part -match  "Client RPC call started") { 
        $side = "Client"
      } else {
        $side = "Server"
      }
      $row = $tbEvt.NewRow()
      $row.Time = $time
      $row.Side = $side
      $row.PID = $LP.PID
      $row.TID = $LP.TID
      $row.InterfaceUuid = FindSep -FindIn $part -Left "InterfaceUuid: `t" -Right " "
      $row.InterfaceName = DecodeIFUUID $row.InterfaceUuid
      $row.OpNum = FindSep -FindIn $part -Left "OpNum: `t" -Right " "
      $row.Protocol = FindSep -FindIn $part -Left "Protocol: `t" -Right " "
      $row.NetworkAddress = FindSep -FindIn $part -Left "NetworkAddress `t" -Right " "
      $row.Endpoint = FindSep -FindIn $part -Left "Endpoint `t" -Right " "
      $row.BindingOptions = FindSep -FindIn $part -Left "Binding Options `t" -Right " "
      $row.AuthenticationLevel = FindSep -FindIn $part -Left "Authentication Level `t" -Right " "
      $row.AuthenticationService = FindSep -FindIn $part -Left "Authentication Service `t" -Right " "
      $row.ImpersonationLevel = FindSep -FindIn $part -Left "Impersonation Level `t" -Right " "
      $tbEvt.Rows.Add($row)
    }
  }
  $line = $sr.ReadLine()
}
$sr.Close()

$file = Get-Item $FileName
$tbEvt | Export-Csv ($file.DirectoryName + "\" + $file.BaseName + ".RPCEvents.csv") -noType

$duration = New-TimeSpan -Start $dtInit -End (Get-Date)
Write-Host "Execution completed in" $duration.TotalSeconds "seconds"

# {e60c73e6-88f9-11cf-9af1-0020af6e72f4} = ILocalObjectExporter
# {4f32adc8-6052-4a04-8701-293ccf2096f0} = sspirpc
# {8a7b5006-cc13-11db-9705-005056c00008} = ??
# {00000136-0000-0000-c000-000000000046} = ISCMLocalActivator
# {00000132-0000-0000-c000-000000000046} = ILocalSystemActivator
# {00000001-0000-0000-c000-000000000046} = IClassFactory
# {00000134-0000-0000-c000-000000000046} = IRundown
# {af86e2e0-b12d-4c6a-9c5a-d7aa65101e90} = IInspectable

# HKEY_CLASSES_ROOT\Interface\