# WMIRPC-TraceParse - 20230615
# by Gianni Bragante - gbrag@microsoft.com

param (
  [string]$FileName
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
  $InQuery = $InQuery.Replace("\\.\", "")
  $FindClass = (FindSep -FindIn $InQuery -Left "from " -Right " ").Trim()

  if ($FindClass -eq "") {
     $FindClass = (FindSep -FindIn $InQuery -Left "from " -Right "").Trim()
     if ($FindClass -eq "") {
       if ($InQuery -match "associators") {
         $FindClass = FindSep -FindIn $InQuery -Left "{" -Right "="
       } else {
         $FindClass = (FindSep -FindIn $InQuery -Left "" -Right " where")
         if ($FindClass -eq "") {
           $FindClass = (FindSep -FindIn $InQuery -Left ":" -Right ".")
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

Function ToTimeP{
  param( [string]$time)
  return Get-Date -Year $time.Substring(6,4) -Month $time.Substring(0,2) -Day $time.Substring(3,2) -Hour $time.Substring(11,2) -Minute $time.Substring(14,2) -Second $time.Substring(17,2) -Millisecond $time.Substring(20,3)
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
  $row.Duration = 0
  $tbEvt.Rows.Add($row)
  Write-host $part
}

Function Parse-Query {
  $row = $tbEvt.NewRow()
  $row.Time = $time
  $row.CorrelationID = FindSep -FindIn $part -Left "CorrelationId = " -Right ";"
  $row.GroupOperationID = FindSep -FindIn $part -Left "GroupOperationId = " -Right ";"
  $row.OperationID = FindSep -FindIn $part -Left " OperationId = " -Right ";"
  $row.ClientMachine = FindSep -FindIn $part -Left "ClientMachine = " -Right ";"
  $row.User = FindSep -FindIn $part -Left "User = " -Right ";"
  $row.ClientPID = FindSep -FindIn $part -Left "ClientProcessId = " -Right ";"

  if ($part -match  "MethodName =") {
    $row.Namespace = FindSep -FindIn $part -Left "NamespaceName = " -Right " {"
    $row.Query = CleanQuery -InQuery (FindSep -FindIn $part -Left "ClassName= " -Right ";").ToLower()
    $row.Operation = FindSep -FindIn $part -Left "MethodName = " -Right ";"
  } else {
    $row.Operation = FindSep -FindIn $part -Left "Start IWbemServices::" -Right " - "
    $row.Namespace = FindSep -FindIn $part -Left ($row.Operation + " - ") -Right " : "
    $row.Query = CleanQuery -InQuery (FindSep -FindIn $part -Left ($row.Namespace + " : ") -Right "; ").ToLower()
  }
  $row.Duration = 0
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
  $row.Duration = 0
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
  $row.Duration = 0
  $tbEvt.Rows.Add($row)
  Write-host $part
}

if ($FileName -eq "") {
  Write-Host "Trace filename not specified"
  exit
}

$KFileName = ""
$bRPC = $false
$fileobj = Get-Item $FileName
if ($fileobj.Basename.ToLower().Contains("-trace")) {  # naming convention for WMI-Collect
  $PerfFileName = (Get-Item($fileobj.DirectoryName + "\*-trace-PerfMonWMIPrvSE-*.blg")).FullName
}

if (-not (Test-Path ($FileName))) {
  Write-Host "WMI trace not found"
  exit
}

if ($fileobj.Basename.ToLower().Contains("-trace")) {  # naming convention for WMI-Collect
  $KFileName = $fileobj.DirectoryName + "\" + $fileobj.Basename.ToLower().Replace("-trace-","-trace-kernel-") + ".txt"
  if (Test-Path ($KFileName)) {
    Write-Host ("Found Kernel trace at " + $KFileName)
    $Kernel = $true
  } else {
    Write-Host "Kernel trace not found"
    $Kernel = $false
  }
} elseif ($fileobj.Basename.ToLower().Contains("_uex_wmi")) {  # naming convention for TSSV2
  if ($fileobj.Basename.ToLower().Contains("_uex_wmibase")) {
    $repl = "_uex_wmibase"
  } else {
    $repl = "_uex_wmiadvanced"
  }
  $KFileName = $fileobj.DirectoryName + "\" + $fileobj.Basename.ToLower().Replace($repl,"_win_kernel") + ".txt"
  if (Test-Path ($KFileName)) {
    Write-Host ("Found Kernel trace at " + $KFileName)
    $Kernel = $true
  } else {
    $repl += "trace-!fmt"
    $KETLName = $fileobj.DirectoryName + "\" + $fileobj.Basename.ToLower().Replace($repl,"_win_kerneltrace") + ".etl"
    if (Test-Path ($KETLName)) {
      Write-Host "The Kernel trace $KETLName has been captured but it is not decoded"  
      exit
    } else {
      Write-Host "Kernel trace not found"
      $Kernel = $false
    }
  }
}

if ($PerfFileName) {
  if (Test-Path ($PerfFileName)) {
    Write-Host ("Found WMIPrvSE performance trace at " + $PerfFileName)
    Write-Host ("relog """ + $PerfFileName + """ -f blg -o """ + $PerfFileName.Replace(".blg", ".csv") + """ -y")
    Invoke-Expression ("relog """ + $PerfFileName + """ -f csv -o """ + $PerfFileName.Replace(".blg", ".csv") + """ -y") | Out-Null
    $PerfWMIPrvSE = $true
    $PerfFileName = $PerfFileName.Replace(".blg", ".csv")
  } else {
    Write-Host "WMIPrvSE performance trace not found"
    $PerfWMIPrvSE = $false
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
             "{d0074ffd-570f-4a9b-8d69-199fdba5723b}" = "INetworkListManager"
             "{11f25515-c879-400a-989e-b074d5f092fe}" = "--"
             "{182c40fa-32e4-11d0-818b-00a0c9231c29}" = "ICatalogSession"
             "{1d118904-94b3-4a64-9fa6-ed432666a7b9}" = "ICatalog64BitSupport"
             "{a8927a41-d3ce-11d1-8472-006008b0e5ca}" = "ICatalogTableInfo"
             "{0e3d6630-b46b-11d1-9d2d-006008b0e5ca}" = "ICatalogTableRead1"
             "{5a648006-843a-4da9-865b-9d26e5dfad7b}" = "IAsyncAction"
             "{2fb92682-6599-42dc-ae13-bd2ca89bd11c}" = "--"
             "{f50aac00-c7f3-428e-a022-a6b71bfb9d43}" = "--"
             "{3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5}" = "DHCPC"
             "{6c323e3f-585f-4432-8a2e-0719fb35e48b}" = "--"
             "{6040ec14-6557-41f9-a3f7-b1cab7b42120}" = "IRuntimeBroker"
             "{8ca8efcc-f4ac-4987-984b-0b92f11c1cd3}" = "__x_Windows_CCortana_CISearchFoldersStatics"
             "{0166231b-fd21-4e33-a713-75eb3207a138}" = "IBackgroundWorkItemInstanceRemote"
             "{e53d94ca-7464-4839-b044-09a2fb8b3ae5}" = "--"
             "{7656cfa4-b63a-4542-a8de-ef402bac895d}" = "IUserApplicationStateChangeHandler"
             "{fc99c60d-d59b-4b2b-b73d-3a1cc9f2aafa}" = "ILifetimeManagerRemote"
             "{b755e6e0-b048-49cc-8911-11a041216f5f}" = "IApplicationStateChangeHandler"
             "{8782d3b9-ebbd-4644-a3d8-e8725381919b}" = "psmApp"
             "{3473dd4d-2e88-4006-9cba-22570909dd10}" = "7-zipn.dll"
             "{9cfeead6-6135-4fcf-831a-fd3b236023f8}" = "--"
             "{6c9b7b96-45a8-4cca-9eb3-e21ccf8b5a89}" = "umpoapi"
             "{8b71bd79-ccbb-47ab-ba09-97ca52c81da9}" = "--"
             "{5f935276-1c7b-46f5-ac77-077759001d2b}" = "--"
             "{02833a34-18e7-4a6d-87ae-a0e707eae0e0}" = "IApplicationTracker"
             "{53825514-1183-4934-a0f4-cfdc51c3389b}" = "TermSrvSessionAppContainer"
             "{959c5a99-177c-478e-8c3b-77e07e9bf3aa}" = "ISessionList"
             "{a1b7de7a-4e77-43db-ae78-96fc182fed4a}" = "ITSSession"
             "{4d10b48b-c531-4731-9bde-b03c28e9c61c}" = "IUserName"
             "{3b338d89-6cfa-44b8-847e-531531bc9992}" = "--"
             "{dd59071b-3215-4c59-8481-972edadc0f6a}" = "--"
             "{886d8eeb-8cf2-4446-8d02-cdba1dbdcf99}" = "IPropertyStore"
             "{7c9d26b6-c493-49b3-b66a-80bef106286b}" = "IObjectWithPropertyStore"
             "{4207a996-ca2f-42f7-bde8-8b10457a7f30}" = "__x_Windows_CStorage_CIStorageItem"
             "{ab310581-ac80-11d1-8df3-00c04fb6ef55}" = "ISearchCrawlScopeManager"
             "{90c5260f-df18-4049-bf47-35d736af4a3e}" = "--"
             "{1b37ca91-76b1-4f5e-a3c7-2abfc61f2bb0}" = "BrokerInfrastructureRuntimeInterface"
             "{a2add09a-fb9b-4e6e-bc69-0b810eeb0ab4}" = "IBackgroundActivationContext"
             "{b18fbab6-56f8-4702-84e0-41053293a869}" = "--"
             "{000001a0-0000-0000-c000-000000000046}" = "ISystemActivator"
             "{82273fdc-e32a-18c3-3f78-827929dc23ea}" = "eventlog"
             "{412f241e-c12a-11ce-abff-0020af6e7a17}" = "ISCM"
             "{1ac7516e-e6bb-4a69-b63f-e841904dc5a6}" = "IEUserBroker"
             "{37a10a44-6f8d-47e9-8376-9cdc326326f4}" = "IShdocvwBroker"
             "{85cb6900-4d95-11cf-960c-0080c7f4ee85}" = "IShellWindows"
             "{b7b31df9-d515-11d3-a11c-00105a1f515a}" = "IWbemShutdown"
             "{52c550c6-067f-4bc8-98b2-0f0e91c10261}" = "IIS W3 Control Interface ProxyStub"
             "{07435309-d440-41b7-83f3-eb82db6c622f}" = "IWmiProviderHost"
             "{06413d98-405c-4a5a-8d6f-19b8b7c6acf7}" = "IWmiProviderFactoryInitialize"
             "{21cd80a2-b305-4f37-9d4c-4534a8d9b568}" = "IWmiProviderFactory"
             "{027947e1-d731-11ce-a357-000000000001}" = "IEnumWbemClassObject"
             "{fec1b0ac-5808-4033-a915-c0185934581e}" = "IWmiProviderSite"
             "{497d95a6-2d27-4bf5-9bbd-a6046957133c}" = "--"
             "{a4b8d482-80ce-40d6-934d-b22a01a44fe7}" = "--"
             "{266f33b4-c7c1-4bd1-8f52-ddb8f2214ea9}" = "--"
             "{ab310581-ac80-11d1-8df3-00c04fb6ef69}" = "ISearchManager"
             "{04c18ccf-1f57-4cbd-88cc-3900f5195ce3}" = "ISearchRoot"
             "{d09bdeb5-6171-4a34-bfe2-06fa82652568}" = "--"
             "{0b0a6584-9e0f-11cf-a3cf-00805f68cb1b}" = "localepmp"
             "{3919286a-b10c-11d0-9ba8-00c04fd92ef5}" = "--"
             "{7f9d11bf-7fb9-436b-a812-b2d50c5d4c03}" = "--"
             "{12345778-1234-abcd-ef00-0123456789ac}" = "--"
             "{30adc50c-5cbc-46ce-9a0e-91914789e23c}" = "--"
             "{86d35949-83c9-4044-b424-db363231fd0c}" = "--"
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
if ($PerfWMIPrvSE) {
  $col = New-Object system.Data.DataColumn CPU,([int16]); $tbEvt.Columns.Add($col)
  $col = New-Object system.Data.DataColumn Memory,([int32]); $tbEvt.Columns.Add($col)
  $col = New-Object system.Data.DataColumn Threads,([int16]); $tbEvt.Columns.Add($col)
  $col = New-Object system.Data.DataColumn Handles,([int16]); $tbEvt.Columns.Add($col)
}
$col = New-Object system.Data.DataColumn OperationID,([int64]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn GroupOperationID,([int64]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn CorrelationID,([string]); $tbEvt.Columns.Add($col)

$tbProv = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Time,([string]); $tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn GroupOperationID,([int64]); $tbProv.Columns.Add($col)
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
$col = New-Object system.Data.DataColumn ExitStatus,([string]); $tbProc.Columns.Add($col)
$col = New-Object system.Data.DataColumn SessionID,([string]); $tbProc.Columns.Add($col)
$col = New-Object system.Data.DataColumn User,([string]); $tbProc.Columns.Add($col)
$col = New-Object system.Data.DataColumn FileName,([string]); $tbProc.Columns.Add($col)
$col = New-Object system.Data.DataColumn CommandLine,([string]); $tbProc.Columns.Add($col)

$tbPerf = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn ("Time",[string]); $tbPerf.Columns.Add($col)
$col = New-Object system.Data.DataColumn Provider,([string]); $tbPerf.Columns.Add($col)
$col = New-Object system.Data.DataColumn PID,([string]); $tbPerf.Columns.Add($col)
$col = New-Object system.Data.DataColumn CPU,([int]); $tbPerf.Columns.Add($col)
$col = New-Object system.Data.DataColumn Handles,([string]); $tbPerf.Columns.Add($col)
$col = New-Object system.Data.DataColumn Memory,([string]); $tbPerf.Columns.Add($col)
$col = New-Object system.Data.DataColumn Threads,([string]); $tbPerf.Columns.Add($col)

$dtInit = Get-Date

$stopwatch =  [system.diagnostics.stopwatch]::StartNew()
$procbytes = 0
$lastProgress = 0
$totbytes = (get-item $FileName).Length

$sr = new-object System.io.streamreader(get-item $FileName)
$line = $sr.ReadLine()
$procbytes = $line.Length
while (-not $sr.EndOfStream) {
  $part = ""
  $part = $line

  while (1 -eq 1) {
    $line = $sr.ReadLine()
    $procbytes += $line.Length
    if ($sr.EndOfStream) { break }
    if ($line.Length -gt 1) {
      if ($line.Substring(0,1) -eq "[") { break }
    }
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
    $bRPC = $True
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
    $procbytes += $line.Length
  }
  if ($stopwatch.Elapsed.TotalSeconds - $lastProgress -gt 10) {
    Write-Host ("====[ Progress: " + ($procbytes / $totbytes * 100) + " % ]====")
    $lastProgress = $stopwatch.Elapsed.TotalSeconds
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
          if ($line -match "Process - End") {
            $aProc[$aProc.Count-1].ExitStatus = (FindSep -FindIn $line -Left "ExitStatus=" -Right ",")
          }
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

if ($PerfWMIPrvSE) {
  $tbPerfTemp = $tbPerf.Clone()

  $sr = new-object System.io.streamreader(get-item $PerfFileName)
  $headerLine = $sr.ReadLine()

  $header = $headerLine.Replace('"', '').Split(",")
  $nCol = $header.Count -1

  $line = $sr.ReadLine()
  while (-not $sr.EndOfStream) {
    $sample = $line.Replace('"', '').Split(",")
    Write-host $sample
    for ($cv = 1; $cv -le $nCol; $cv++) {
      $dt = (ToTimeP $sample[0]).ToString("yyyyMMdd HHmmss")
      $Prov = FindSep -FindIn $header[$cv] -Left "(" -Right ")"
      $aProvRow = $tbPerfTemp.Select("Time = '$dt' and Provider = '" + $Prov + "'")
      if (-not $aProvRow) {
        $row = $tbPerfTemp.NewRow()
        $row.Time = $dt
        $row.Provider = $Prov
        $tbPerfTemp.Rows.Add($row)
        $aProvRow = $tbPerfTemp.Select("Time = '$dt' and Provider = '" + $Prov + "'")
      }      
      if ($header[$cv] -match "Processor Time") {
        $aProvRow[0].CPU = [int]$sample[$cv].Trim()
      } elseif ($header[$cv] -match "Thread") {
        $aProvRow[0].Threads = $sample[$cv]
      } elseif ($header[$cv] -match "ID Process") {
        $aProvRow[0].PID = $sample[$cv]
      } elseif ($header[$cv] -match "Handle") {
        $aProvRow[0].Handles = $sample[$cv]
      } elseif ($header[$cv] -match "Working Set") {
        $aProvRow[0].Memory = $sample[$cv]
      }
    }
    foreach ($row in $tbPerfTemp.Rows) {
      if ($row.PID -gt 0) {
        $newRow = $tbPerf.NewRow()
        foreach ($column in $tbPerfTemp.Columns) {
          $newRow[$column.ColumnName] = $row[$column.ColumnName]
        }
        $tbPerf.Rows.Add($newRow)
      }
    }
    $tbPerfTemp.Rows.Clear()
    $line = $sr.ReadLine()
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
      if ($PerfWMIPrvSE) {
        $duration = if ($row.Duration -lt 1000) { 1000 } else { $row.Duration }
        $tStart = (ToTime $row.Time)
        $tEnd = $tstart.AddSeconds($duration / 1000)
        $sel = "Time >= '" + $tStart.ToString("20yyMMdd HHmmss") + "' and Time <= '" + $tEnd.ToString("20yyMMdd HHmmss") + "' and PID = '" + $row.HostID + "'"
        $aPerf = $tbPerf.Select($sel)
        if ($aPerf) {
          $CPU = 0
          $Memory = 0
          $Handles = 0
          $Threads = 0
          for ($cv = 0; $cv -le $aPerf.Count-1; $cv++) {
            $CPU+= $aPerf[$cv].CPU
            $Memory+= $aPerf[$cv].Memory
            $Threads+= $aPerf[$cv].Threads
            $Handles+= $aPerf[$cv].Handles
          }
          $row.CPU = ($CPU / $aPerf.Count)
          #$row.CPU = $CPU  <==== it is better to provide the average or the sum for queries lasting longer than one second?
          $row.Memory = ($Memory / $aPerf.Count)
          $row.Threads = ($Threads / $aPerf.Count)
          $row.Handles = ($Handles / $aPerf.Count)
        }
      }
    }
  }
}

$file = Get-Item $FileName
$tbEvt | Export-Csv ($file.DirectoryName + "\" + $file.BaseName + ".queries.csv") -noType
$tbProv | Export-Csv ($file.DirectoryName + "\" + $file.BaseName + ".providers.csv") -noType
$tbProc | Export-Csv ($file.DirectoryName + "\" + $file.BaseName + ".processes.csv") -noType

if ($bRPC) {
  $tbRPC | Export-Csv ($file.DirectoryName + "\" + $file.BaseName + ".RPCEvents.csv") -noType
}

if ($PerfWMIPrvSE) {
  $tbPerf | Export-Csv ($file.DirectoryName + "\" + $file.BaseName + ".perf.csv") -noType
}

$duration = New-TimeSpan -Start $dtInit -End (Get-Date)
Write-Host "Execution completed in" $duration.TotalSeconds "seconds"

