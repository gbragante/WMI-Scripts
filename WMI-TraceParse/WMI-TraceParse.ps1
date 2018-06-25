# WMI-TraceParse - 20180625
# by Gianni Bragante - gbrag@microsoft.com

param (
  [string]$FileName
)

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
  if ($row.CorrelationID -eq "{CD7B543B-F23B-0000-AA80-AFCD3BF2D301}") {
    Write-Host "jjj"
  }

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

$KFileName = $FileName.ToLower().Replace("wmi-trace-","wmi-trace-kernel-")

if (-not (Test-Path ($FileName))) {
  Write-Host "WMI trace not found"
  exit
}

if (Test-Path ($KFileName)) {
  $Kernel = $true
} else {
  Write-Host "Kernel trace not found"
  $Kernel = $false
}

$tbEvt = New-Object system.Data.DataTable �evt�
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

$tbProv = New-Object system.Data.DataTable �prov�
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

$tbProc = New-Object system.Data.DataTable �proc�
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
    $line = $sr.ReadLine()
  }
  $sr.Close()
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
$tbProc | Export-Csv ($file.DirectoryName + "\" + $file.BaseName + ".processes.csv") -noType

$duration = New-TimeSpan -Start $dtInit -End (Get-Date)
Write-Host "Execution completed in" $duration.TotalSeconds "seconds"

