# RPC-TraceParse - 20210329
# by Gianni Bragante - gbrag@microsoft.com

param (
  [string]$FileName = "C:\files\RPC-TraceParse\wmi-trace-hjcm-cas-new-!FMT.txt"
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

Function ToTime{
  param( [string]$time)
  return Get-Date -Year $time.Substring(6,2) -Month $time.Substring(0,2) -Day $time.Substring(3,2) -Hour $time.Substring(9,2) -Minute $time.Substring(12,2) -Second $time.Substring(15,2) -Millisecond $time.Substring(18,3)
}


Function DecodeIFUUID {
  # HKEY_CLASSES_ROOT\Interface\ is too slow
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
             "{af86e2e0-b12d-4c6a-9c5a-d7aa65101e90}" = "IInspectable";
             "{16ae6386-0aa2-45fc-aab2-f2ee3a0f3188}" = "IEventLoggerFactory";
             "{a3104ea9-a816-4fdc-860c-75408a04b686}" = "IEventLogger"
             "{fb8a0729-2d04-4658-be93-27b4ad553fac}" = "lsalook";
             "{9b8699ae-0e44-47b1-8e7f-86a461d7ecdc}" = "IActivationKernel";
             "{367abb81-9844-35f1-ad32-98f038001003}" = "svcctl";
             "{d4781cd6-e5d3-44df-ad94-930efe48a887}" = "IWbemLoginClientID";
             "{9f6c78ef-fce5-42fa-abea-3e7df91921dc}" = "IWbemLoginClientIDEx";
             "{f309ad18-d86a-11d0-a075-00c04fb68820}" = "IWbemLevel1Login";
             "{9556dc99-828c-11cf-a37e-00aa003240c7}" = "IWbemServices";
             "{e1af8308-5d1f-11c9-91a4-08002b14a0fa}" = "epmp";
             "{c605f9fb-f0a3-4e2a-a073-73560f8d9e3e}" = "??";
             "{7c857801-7381-11cf-884d-00aa004b2e24}" = "PSFactoryBuffer"
             "{6b3fc272-bf37-4968-933a-6df9222a2607}" = "_IWmiProviderConfiguration"
             "{1c1c45ee-4395-11d2-b60b-00104b703efd}" = "IWbemFetchSmartEnum"
             "{423ec01e-2e35-11d2-b604-00104b703efd}" = "IWbemWCOSmartEnum"
             "{11220835-5b26-4d94-ae86-c3e475a809de}" = "ICryptProtect"
             "{4bec6bb8-b5c2-4b6f-b2c1-5da5cf92d0d9}" = "??"
             "{085b0334-e454-4d91-9b8c-4134f9e793f3}" = "??"
             "{9d420415-b8fb-4f4a-8c53-4502ead30ca9}" = "??"
             "{c6f3ee72-ce7e-11d1-b71e-00c04fc3111a}" = "IMachineActivatorControl"
             "{f6beaff7-1e19-4fbb-9f8f-b89e2018337c}" = "??"
             "{15cd3850-28ca-11ce-a4e8-00aa006116cb}" = "??"
             "{c503f532-443a-4c69-8300-ccd1fbdb3839}" = "XPVPROPS.DLL"
             "{99fcfec4-5260-101b-bbcb-00aa0021347a}" = "IObjectExporter"
             "{12345678-1234-abcd-ef00-01234567cffb}" = "logon"
            }

$tbEvt = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Time,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Side,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn PID,([int32]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn TID,([int32]); $tbEvt.Columns.Add($col)
if ($Kernel) {
  $col = New-Object system.Data.DataColumn Process,([string]); $tbEvt.Columns.Add($col)
}
$col = New-Object system.Data.DataColumn Status,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Duration,([int32]); $tbEvt.Columns.Add($col)
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

$tbProc = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn PID,([int32]); $tbProc.Columns.Add($col)
$col = New-Object system.Data.DataColumn Parent,([int32]); $tbProc.Columns.Add($col)
$col = New-Object system.Data.DataColumn Start,([string]); $tbProc.Columns.Add($col)
$col = New-Object system.Data.DataColumn Stop,([string]); $tbProc.Columns.Add($col)
$col = New-Object system.Data.DataColumn SessionID,([string]); $tbProc.Columns.Add($col)
$col = New-Object system.Data.DataColumn User,([string]); $tbProc.Columns.Add($col)
$col = New-Object system.Data.DataColumn FileName,([string]); $tbProc.Columns.Add($col)
$col = New-Object system.Data.DataColumn CommandLine,([string]); $tbProc.Columns.Add($col)

$dtInit = Get-Date

$sr = new-object System.io.streamreader(get-item $FileName)
$line = $sr.ReadLine()
while (-not $sr.EndOfStream) {
  $part = ""
  $part = $line

  $npos = $part.IndexOf("::")
  $time = ($part.Substring($nPos + 2 , 25))
  
  if ($part -match  "\[Debug \]" -or $part -match  "\[Debug17 \]") { 
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

    if ($part -match  "completed.") {
      Write-Host $part
      if ($part -match  "Client RPC call completed") { 
        $side = "Client"
      } else {
        $side = "Server"
      }
      $aEvt = $tbEvt.Select("PID = '" + $LP.PID + "' and TID = '" + $LP.TID + "' and Side = '$Side' and Duration is Null")
      if ($aEvt.Count -gt 0) { 
        $dtStart = ToTime $aEvt[0].Time
        $dtEnd = ToTime $LP.Time
        $duration = New-TimeSpan -Start $dtStart -End $dtEnd    
        $aEvt[0].Duration = $duration.TotalMilliseconds
        $aEvt[0].Status = (FindSep -FindIn $part -Left "Status:").Trim()
      }
    }
  }
  $line = $sr.ReadLine()
}
$sr.Close()

if ($Kernel) {
  Write-Host "Processing Kernel trace"
  $sr = new-object System.io.streamreader(get-item $KFileName)
  $line = $sr.ReadLine()
  while (-not $sr.EndOfStream) {
    $npos = $line.IndexOf("::")
    if ($nPos -gt 0) {
      $time = ($line.Substring($nPos + 2 , 25))

      if (($line -match "Process - DCStart") -or ($line -match "Process - Start")) {
        $row = $tbProc.NewRow()
        $row.Start = $time
        $row.PID = [int32](FindSep -FindIn $line -Left "ProcessId=" -Right ",")
        $row.Parent = [int32](FindSep -FindIn $line -Left "ParentId=" -Right ",")
        $row.SessionId = FindSep -FindIn $line -Left "SessionId=" -Right ","
        $row.User = (FindSep -FindIn $line -Left "UserSID=" -Right ",").Replace("\\","")
        $row.FileName= (FindSep -FindIn $line -Left "FileName=" -Right ",")
        $row.CommandLine = (FindSep -FindIn $line -Left "CommandLine=" -Right ",").Replace("\??\","")
        $tbProc.Rows.Add($row)
        Write-host $line
      }

      if (($line -match "Process - End") -or ($line -match "Process - DCEnd")) {
        $ProcID = [int32](FindSep -FindIn $line -Left "ProcessId=" -Right ",")    
        $aProc = $tbProc.Select("PID = " + $ProcID)
        if ($aProc.Count -gt 0) {
          $aProc[$aProc.Count-1].Stop = $time
        }
      }
    }
    $line = $sr.ReadLine()
  }
  $sr.Close()

  Write-Host "Decoding process in the events"
  foreach ($row in $tbEvt.Rows) {
    Write-Host $row.Time $row.Side $row.InterfaceUuid
    $aProc = $tbProc.Select("PID = " + $row.PID + " and Stop > '" + $row.Time + "'")
    if ($aProc.Count -gt 0) {
      $row.Process = $aProc[$aProc.Count-1].FileName
    }
  }
}

$file = Get-Item $FileName
$tbEvt | Export-Csv ($file.DirectoryName + "\" + $file.BaseName + ".RPCEvents.csv") -noType
$tbProc | Export-Csv ($file.DirectoryName + "\" + $file.BaseName + ".processes.csv") -noType
$duration = New-TimeSpan -Start $dtInit -End (Get-Date)
Write-Host "Execution completed in" $duration.TotalSeconds "seconds"



