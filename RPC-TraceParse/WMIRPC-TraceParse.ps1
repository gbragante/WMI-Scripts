# WMIRPC-TraceParse - 20210330
# by Gianni Bragante - gbrag@microsoft.com

param (
  [string]$FileName = "C:\files\RPC-TraceParse\wmi-trace-gbrag-t470s-!FMT.txt"
)

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

Function FindClass {
  param( [string] $InQuery, [string]$Quote)
  $FindClass = (FindSep -FindIn $InQuery -Left "from " -Right " ").Trim()
  if ($FindClass -eq "") {
     $FindClass = (FindSep -FindIn $InQuery -Left "from " -Right "").Trim()
     if ($FindClass -eq "") {
       if ($InQuery -match "associators") {
         $FindClass = FindSep -FindIn $InQuery -Left "{" -Right "="
       } else {
         $FindClass = (FindSep -FindIn $InQuery -Left "" -Right " where")
         if ($FindClass -eq "") {
           $FindClass = (FindSep -FindIn $InQuery -Left "" -Right ".")
           if ($FindClass -eq "") {
             $FindClass = (FindSep -FindIn $InQuery -Left "" -Right "::")
             if ($FindClass -eq "") {
               $FindClass = $InQuery.Replace("'", $Quote)
             }
           }                        
         }
       }
     }
   }
   return $FindClass
}

Function CleanQuery {
  param([string] $InQuery)
  $try = 0
  while ($InQuery.IndexOf("  ") -ge 0 -and $try -lt 20) {
    $InQuery = $InQuery.Replace("  ", " ")
    $try++
  }
  return $InQuery
}

Function ToTime{
  param( [string]$time)
  return Get-Date -Year $time.Substring(6,2) -Month $time.Substring(0,2) -Day $time.Substring(3,2) -Hour $time.Substring(9,2) -Minute $time.Substring(12,2) -Second $time.Substring(15,2) -Millisecond $time.Substring(18,3)
}

Function Parse-ProviderInfo {
  $row = $tbProv.NewRow()
  $row.Time = $time
  $row.GroupOperationID = FindSep -FindIn $part -Left "GroupOperationId = " -Right ";"
  $row.Operation = FindSep -FindIn $part -Left "Operation = Provider::" -Right " - "
  $Namespace = FindSep -FindIn $part -Left ($row.Operation + " - ") -Right " : "
  $row.Query = CleanQuery -InQuery (FindSep -FindIn $part -Left ($Namespace + " : ") -Right "; ").ToLower()        
  $row.Class = FindClass $row.Query "''"
  $row.HostID = FindSep -FindIn $part -Left "HostID = " -Right ";"
  $row.ProviderName = FindSep -FindIn $part -Left "ProviderName = " -Right ";"
  $row.ProviderGuid = FindSep -FindIn $part -Left "ProviderGuid = " -Right ";"
  $row.Path = FindSep -FindIn $part -Left "Path = " -Right ";"
  $tbProv.Rows.Add($row)
  Write-Host $part          
}

Function Parse-ProviderStarted {
  $row = $tbProv.NewRow()
  $row.Time = $time
  $row.Operation = "Start"
  $row.HostID = FindSep -FindIn $part -Left "ProcessID = " -Right ";"
  $row.ProviderName = FindSep -FindIn $part -Left "] " -Right " provider"
  $row.Path = FindSep -FindIn $part -Left "ProviderPath = " -Right ""
  $row.ResultCode = FindSep -FindIn $part -Left "result code " -Right "."
  $tbProv.Rows.Add($row)
}

Function Parse-ConnectToNamespace {
  $row = $tbEvt.NewRow()
  $row.Time = $time
  $row.Operation = "ConnectToNamespace"
  $row.Namespace = FindSep -FindIn $part -Left "namespace : " -Right ";"
  $row.ClientMachine = FindSep -FindIn $part -Left "ClientMachine = " -Right ";"
  $row.User = FindSep -FindIn $part -Left "User = " -Right ";"
  $row.ClientPID = FindSep -FindIn $part -Left "ClientProcessId = " -Right ";"
  $row.ResultCode = FindSep -FindIn $part -Left "ResultCode = " -Right ";"
  $row.PossibleCause = FindSep -FindIn $part -Left "PossibleCause = " -Right "."
  $tbEvt.Rows.Add($row)
  Write-host $part
}

Function Parse-Query {
  $row = $tbEvt.NewRow()
  $row.Time = $time
  $row.CorrelationID = FindSep -FindIn $part -Left "CorrelationId = " -Right ";"
  $row.GroupOperationID = FindSep -FindIn $part -Left "GroupOperationId = " -Right ";"
  $row.OperationID = FindSep -FindIn $part -Left " OperationId = " -Right ";"
  $row.Operation = FindSep -FindIn $part -Left "Start IWbemServices::" -Right " - "
  $row.Namespace = FindSep -FindIn $part -Left ($row.Operation + " - ") -Right " : "
  $row.Query = CleanQuery -InQuery (FindSep -FindIn $part -Left ($row.Namespace + " : ") -Right "; ").ToLower()
  $row.ClientMachine = FindSep -FindIn $part -Left "ClientMachine = " -Right ";"
  $row.User = FindSep -FindIn $part -Left "User = " -Right ";"
  $row.ClientPID = FindSep -FindIn $part -Left "ClientProcessId = " -Right ";"
  $tbEvt.Rows.Add($row)
  Write-host $part
}

Function Parse-Query_ {
  $row = $tbEvt.NewRow()
  $row.Time = $time
  $row.CorrelationID = FindSep -FindIn $part -Left "CorrelationId = " -Right ";"
  $row.GroupOperationID = FindSep -FindIn $part -Left "GroupOperationId = " -Right ";"
  $row.OperationID = FindSep -FindIn $part -Left " OperationId = " -Right ";"
  $row.ClientMachine = FindSep -FindIn $part -Left "ClientMachine = " -Right ";"
  $row.User = FindSep -FindIn $part -Left "User = " -Right ";"
  $row.ClientPID = FindSep -FindIn $part -Left "ClientProcessId = " -Right ";"

  if ($part -match  "MethodName =") {
    $row.Namespace = FindSep -FindIn $part -Left "NamespaceName = " -Right "  {"
    $row.Query = CleanQuery -InQuery (FindSep -FindIn $part -Left "ClassName= " -Right ";").ToLower()
    $row.Operation = FindSep -FindIn $part -Left "MethodName = " -Right ";"
  } else {
    $row.Operation = FindSep -FindIn $part -Left "Start IWbemServices::" -Right " - "
    $row.Namespace = FindSep -FindIn $part -Left ($row.Operation + " - ") -Right " : "
    $row.Query = CleanQuery -InQuery (FindSep -FindIn $part -Left ($row.Namespace + " : ") -Right "; ").ToLower()
  }
  $tbEvt.Rows.Add($row)
  Write-host $part
}

Function Parse-StopOperationID {
  $OperationID = FindSep -FindIn $part -Left "OperationId = " -Right ";"     
  $aOpId = $tbEvt.Select("OperationID = '" + $OperationID + "'")        
  if ($aOpId.Count -gt 0) { 
    $ResultCode = FindSep -FindIn $part -Left "ResultCode = " -Right ""
    $dtStart = ToTime $aOpId[0].Time
    $dtEnd = ToTime $time
    $duration = New-TimeSpan -Start $dtStart -End $dtEnd    
    $aOpId[0].ResultCode = $ResultCode
    $aOpId[0].Duration = $duration.TotalMilliseconds
  } 
}

Function Parse-ProviderQuery {
  $Operation = FindSep -FindIn $part -Left "Operation = " -Right " - "
  $NameSpace = FindSep -FindIn $part -Left ($Operation + " - ") -Right " : "
  $Query = CleanQuery -InQuery (FindSep -FindIn $part -Left ($NameSpace + " : ")  -Right ";").Replace("'","''")
      
   $select  = "CorrelationID = '" + $CorrelationID + "' and Query = '" + $query + "'"
   $aOpId = $tbEvt.Select($select)
   if ($aOpId.Count -gt 0) { 
     $item = $aOpId.Count - 1
     $ResultCode = FindSep -FindIn $part -Left "ResultCode = " -Right ";"
     $PossibleCause = FindSep -FindIn $part -Left "PossibleCause = " -Right ""

     $dtStart = ToTime $aOpId[0].Time
     $dtEnd = ToTime $time
     $duration = New-TimeSpan -Start $dtStart -End $dtEnd
          
     $aOpId[$item].ResultCode = $ResultCode
     $aOpId[$item].PossibleCause = $PossibleCause
     $aOpId[$item].Duration = $duration.TotalMilliseconds
   }
}

Function Parse-Polling {
  $row = $tbEvt.NewRow()
  $row.Time = $time
  $row.Operation = "Polling"
  $row.Namespace = (FindSep -FindIn $part -Left "'//./" -Right "'").ToLower().Replace("/","\")
  $row.Query = CleanQuery -InQuery (FindSep -FindIn $part -Left "query '" -Right "'").ToLower()
  $tbEvt.Rows.Add($row)
  Write-host $part
}

if ($FileName -eq "") {
  Write-Host "Trace filename not specified"
  exit
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
             "{8a7b5006-cc13-11db-9705-005056c00008}" = "--";
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
             "{c605f9fb-f0a3-4e2a-a073-73560f8d9e3e}" = "--";
             "{7c857801-7381-11cf-884d-00aa004b2e24}" = "PSFactoryBuffer"
             "{6b3fc272-bf37-4968-933a-6df9222a2607}" = "_IWmiProviderConfiguration"
             "{1c1c45ee-4395-11d2-b60b-00104b703efd}" = "IWbemFetchSmartEnum"
             "{423ec01e-2e35-11d2-b604-00104b703efd}" = "IWbemWCOSmartEnum"
             "{11220835-5b26-4d94-ae86-c3e475a809de}" = "ICryptProtect"
             "{4bec6bb8-b5c2-4b6f-b2c1-5da5cf92d0d9}" = "--"
             "{085b0334-e454-4d91-9b8c-4134f9e793f3}" = "--"
             "{9d420415-b8fb-4f4a-8c53-4502ead30ca9}" = "--"
             "{c6f3ee72-ce7e-11d1-b71e-00c04fc3111a}" = "IMachineActivatorControl"
             "{f6beaff7-1e19-4fbb-9f8f-b89e2018337c}" = "--"
             "{15cd3850-28ca-11ce-a4e8-00aa006116cb}" = "--"
             "{c503f532-443a-4c69-8300-ccd1fbdb3839}" = "XPVPROPS.DLL"
             "{99fcfec4-5260-101b-bbcb-00aa0021347a}" = "IObjectExporter"
             "{12345678-1234-abcd-ef00-01234567cffb}" = "logon"
             "{12345778-1234-abcd-ef00-0123456789ab}" = "lsarpc"
             "{00000143-0000-0000-c000-000000000046}" = "IRemUnknown2"
             "{49cf325d-12be-47eb-91c8-d74ab3479f92}" = "--"
             "{84cb7bf8-4684-4980-84cf-2c99fd3ceffa}" = "--"
             "{6bffd098-a112-3610-9833-46c3f87e345a}" = "--"
             "{4b324fc8-1670-01d3-1278-5a47bf6ee188}" = "--"
             "{88143fd0-c28d-4b2b-8fef-8d882f6a9390}" = "--"
             "{1a8a5d71-d95b-4dcd-915e-f9f6d31879ad}" = "ITerminal"
             "{bde95fdf-eee0-45de-9e12-e5a61cd0d4fe}" = "--"
             "{484809d6-4239-471b-b5bc-61df8c23ac48}" = "--"
             "{45776b01-5956-4485-9f80-f428f7d60129}" = "--"
             "{3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6}" = "DHCPV6C"
             "{0d72a7d4-6148-11d1-b4aa-00c04fb66ea0}" = "ICertProtectFunctions"
             "{a2c45f7c-7d32-46ad-96f5-adafb486be74}" = "--"
             "{cad784cb-4c1b-4d96-b8f7-4716b568b13c}" = "--"
             "{dd490425-5325-4565-b774-7e27d6c09c24}" = "BFE"
             "{17a643ed-26bc-4afa-b545-1bbbe77dbc30}" = "ITabWindow2"
             "{feefb420-9399-492d-969c-51af6dc38fb1}" = "ITabWindowManager"
             "{7f3c143a-6083-48f4-a997-56040a4c1d51}" = "IBrowserFrame"
            }

$tbEvt = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Time,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn ClientPID,([int32]); $tbEvt.Columns.Add($col)
if ($Kernel) {
  $col = New-Object system.Data.DataColumn Process,([string]); $tbEvt.Columns.Add($col)
}
$col = New-Object system.Data.DataColumn Namespace,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Operation,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Query,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Duration,([int32]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn ResultCode,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn PossibleCause,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn ClientMachine,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn User,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn HostID,([int32]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn ProviderName,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn OperationID,([int32]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn GroupOperationID,([int32]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn CorrelationID,([string]); $tbEvt.Columns.Add($col)

$tbProv = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Time,([string]); $tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn GroupOperationID,([int32]); $tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn Operation,([string]); $tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn Query,([string]); $tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn Class,([string]); $tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn HostID,([int32]); $tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn ResultCode,([string]); $tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn ProviderName,([string]); $tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn ProviderGuid,([string]); $tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn Path,([string]); $tbProv.Columns.Add($col)

$tbRPC = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Time,([string]); $tbRPC.Columns.Add($col)
$col = New-Object system.Data.DataColumn Side,([string]); $tbRPC.Columns.Add($col)
$col = New-Object system.Data.DataColumn PID,([int32]); $tbRPC.Columns.Add($col)
$col = New-Object system.Data.DataColumn TID,([int32]); $tbRPC.Columns.Add($col)
if ($Kernel) {
  $col = New-Object system.Data.DataColumn Process,([string]); $tbRPC.Columns.Add($col)
}
$col = New-Object system.Data.DataColumn Status,([string]); $tbRPC.Columns.Add($col)
$col = New-Object system.Data.DataColumn Duration,([int32]); $tbRPC.Columns.Add($col)
$col = New-Object system.Data.DataColumn InterfaceUuid,([string]); $tbRPC.Columns.Add($col)
$col = New-Object system.Data.DataColumn InterfaceName,([string]); $tbRPC.Columns.Add($col)
$col = New-Object system.Data.DataColumn OpNum,([string]); $tbRPC.Columns.Add($col)
$col = New-Object system.Data.DataColumn Protocol,([string]); $tbRPC.Columns.Add($col)
$col = New-Object system.Data.DataColumn NetworkAddress,([string]); $tbRPC.Columns.Add($col)
$col = New-Object system.Data.DataColumn Endpoint,([string]); $tbRPC.Columns.Add($col)
$col = New-Object system.Data.DataColumn BindingOptions,([string]); $tbRPC.Columns.Add($col)
$col = New-Object system.Data.DataColumn AuthenticationLevel,([string]); $tbRPC.Columns.Add($col)
$col = New-Object system.Data.DataColumn AuthenticationService,([string]); $tbRPC.Columns.Add($col)
$col = New-Object system.Data.DataColumn ImpersonationLevel,([string]); $tbRPC.Columns.Add($col)

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

  while (1 -eq 1) {
    $line = $sr.ReadLine()
    if ($sr.EndOfStream) { break }
    if ($line.Substring(0,1) -eq "[") { break }
    $part = $part + $line
  }

  $npos = $part.IndexOf("::")
  $time = ($part.Substring($nPos + 2 , 25))
  
  if ($part -match  "\[Microsoft-Windows-WMI-Activity/Trace\]") { 
    if ($part -match  "CorrelationId =") {  
      if ($part -match  "Protocol = DCOM") {
      } else {
        if ($part -match  "::Connect") {
        } else {    
          Parse-Query
        }
      }
    } else {
      if ($part -match  "Stop OperationId") {
        Parse-StopOperationID
      } else {
        if ($part -match  "ProviderInfo for GroupOperationId") {
          Parse-ProviderInfo
        }
      }
    }
  }

  if ($part -match  "\[Microsoft_Windows_WMI_Activity/Trace") { 
    if ($part -match  "CorrelationId =") {  
      if ($part -match  "Protocol = DCOM") {
      } else {
        if ($part -match  "::Connect") {
        } else {    
          Parse-Query_
        }
      }
    } else {
      if ($part -match  "Stop OperationId") {
        Parse-StopOperationID
      } else {
        if ($part -match  "ProviderInfo for GroupOperationId") {
          Parse-ProviderInfo
        }
      }
    }
  }

  if ($part -match  "\[Microsoft-Windows-WMI-Activity/Operational\]") {
    $CorrelationID = FindSep -FindIn $part -Left "Id = " -Right ";"
    if ($CorrelationID -eq "") {
      if ($part -match "provider started with result code") {
        Parse-ProviderStarted
      } elseif ($part -match "Operation = connect to namespace") {
        Parse-ConnectToNamespace
      }
    } else { 
      Parse-ProviderQuery    
    }
    Write-Host $part
  }
  if ($part -match  "Executing polling query") { 
    Parse-Polling
  }

  if ($part -match  "\[Debug \]" -or $part -match  "\[Debug17 \]") { 
    $LP = LineParam
    if ($part -match  "RPC call started") {
      Write-Host $part
      if ($part -match  "Client RPC call started") { 
        $side = "Client"
      } else {
        $side = "Server"
      }
      $row = $tbRPC.NewRow()
      $row.Time = $LP.Time
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
      $tbRPC.Rows.Add($row)
    }

    if ($part -match  "completed.") {
      Write-Host $part
      if ($part -match  "Client RPC call completed") { 
        $side = "Client"
      } else {
        $side = "Server"
      }
      $aEvt = $tbRPC.Select("PID = '" + $LP.PID + "' and TID = '" + $LP.TID + "' and Side = '$Side' and Duration is Null")
      if ($aEvt.Count -gt 0) { 
        $dtStart = ToTime $aEvt[0].Time
        $dtEnd = ToTime $LP.Time
        $duration = New-TimeSpan -Start $dtStart -End $dtEnd    
        $aEvt[0].Duration = $duration.TotalMilliseconds
        $aEvt[0].Status = (FindSep -FindIn $part -Left "Status:").Trim()
      }
    }
  }

  if ($part -eq "") {
    $line = $sr.ReadLine()
  }
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

  Write-Host "Decoding process in the RPC events"
  foreach ($row in $tbRPC.Rows) {
    Write-Host $row.Time $row.Side $row.InterfaceUuid
    $aProc = $tbProc.Select("PID = " + $row.PID + " and Stop > '" + $row.Time + "'")
    if ($aProc.Count -gt 0) {
      $row.Process = $aProc[$aProc.Count-1].FileName
    }
  }
}

Write-Host "Processing providers and process information"
foreach ($row in $tbEvt.Rows) {
  if ($row.Query.ToString() -ne "") {
    Write-Host $row.Time $row.operation $row.query
    if ($row.Operation -ne "Polling") {
      $aProv = $tbProv.Select("GroupOperationID = '" + $row.GroupOperationID + "' and Query = '" + $row.Query.Replace("'","""") + "' and time >='" + $row.Time + "'")
      if ($aProv.Count -gt 0) {
        $row.HostID = $aProv[0].HostID
        $row.ProviderName = $aProv[0].ProviderName
      } else {
        $Class = FindClass $row.Query """"
        $aProv = $tbProv.Select("GroupOperationID = '" + $row.GroupOperationID + "' and Class = '" + $Class + "' and time >='" + $row.Time + "'")
        if ($aProv.Count -gt 0) {
          $row.HostID = $aProv[0].HostID
          $row.ProviderName = $aProv[0].ProviderName
        } else {
          $aProv = $tbProv.Select("Class = '" + $Class + "' and time >='" + $row.Time + "'")
          if ($aProv.Count -gt 0) {
            $row.HostID = $aProv[0].HostID
            $row.ProviderName = $aProv[0].ProviderName
            $row.GroupOperationID = $aProv[0].GroupOperationID
          }
        }
      }
      if ($Kernel) {
        $aProc = $tbProc.Select("PID = " + $row.ClientPID + " and Stop > '" + $row.Time + "'")
        if ($aProc.Count -gt 0) {
          $row.Process = $aProc[$aProc.Count-1].FileName
        }
      }
    }
  }
}

$file = Get-Item $FileName
$tbEvt | Export-Csv ($file.DirectoryName + "\" + $file.BaseName + ".queries.csv") -noType
$tbProv | Export-Csv ($file.DirectoryName + "\" + $file.BaseName + ".providers.csv") -noType
$tbRPC | Export-Csv ($file.DirectoryName + "\" + $file.BaseName + ".RPCEvents.csv") -noType
$tbProc | Export-Csv ($file.DirectoryName + "\" + $file.BaseName + ".processes.csv") -noType

$duration = New-TimeSpan -Start $dtInit -End (Get-Date)
Write-Host "Execution completed in" $duration.TotalSeconds "seconds"

