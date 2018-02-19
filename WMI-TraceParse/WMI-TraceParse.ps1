# WMI-TraceParse - 20180216
# by Gianni Bragante - gbrag@microsoft.com

param (
  [string]$FileName
)

Function FindSep {
  param( [string]$FindIn, [string]$Left,[string]$Right )
  $Start = $FindIn.IndexOf($Left) + $Left.Length

  $Start = $FindIn.IndexOf($Left) 
  if ($Start -gt 0 ) {
     $Start = $Start + $Left.Length
  } else {
     return ""
  }

  if ($Right -eq "") {
    $End = $FindIn.Substring($Start).Length
  } else {
    $End = $FindIn.Substring($Start).IndexOf($Right)
    if ($end -le 0) {
      $End = $FindIn.Substring($Start).Length
    }
  }
  $Found = $FindIn.Substring($Start, $End)
  return $Found
}

Function ToTime{
  param( [string]$time)
  return Get-Date -Year $time.Substring(6,2) -Month $time.Substring(0,2) -Day $time.Substring(3,2) -Hour $time.Substring(9,2) -Minute $time.Substring(12,2) -Second $time.Substring(15,2) -Millisecond $time.Substring(18,3)
}

if ($FileName -eq "") {
  Write-Host "Trace filename not specified"
  exit
}

$lines = 0
$xmlLine = @{}

$tbEvt = New-Object system.Data.DataTable “evt”
$col = New-Object system.Data.DataColumn Time,([string])
$tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn ClientPID,([string])
$tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Namespace,([string])
$tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Operation,([string])
$tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Query,([string])
$tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Duration,([string])
$tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn ResultCode,([string])
$tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn ClientMachine,([string])
$tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn User,([string])
$tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn OperationID,([string])
$tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn GroupOperationID,([string])
$tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn CorrelationID,([string])
$tbEvt.Columns.Add($col)

$dtInit = Get-Date

$sr = new-object System.io.streamreader(get-item $FileName)
$line = $sr.ReadLine()
$lines = $lines + 1
while (-not $sr.EndOfStream) {
  $part = ""
  if ($line -match  "\[Microsoft-Windows-WMI-Activity/Trace\]") {
    
    $npos=$line.IndexOf("::")
    $time = ($line.Substring($nPos + 2 , 25))

    $part = $line
    $line = $sr.ReadLine()
    if ($line.substring(0,1) -ne "[" ) {
      $part = $part + $line
    }

    if ($part -match  "CorrelationId =") {  
      if ($part -match  "Protocol = DCOM") {
      } else {
        if ($part -match  "::Connect") {
        } else {    
          $row = $tbEvt.NewRow()
          $row.Time = $time
          $row.CorrelationID = FindSep -FindIn $part -Left "CorrelationId = " -Right ";"
          $row.GroupOperationID = FindSep -FindIn $part -Left "GroupOperationId = " -Right ";"
          $row.OperationID = FindSep -FindIn $part -Left " OperationId = " -Right ";"
          $row.Operation = FindSep -FindIn $part -Left "Start IWbemServices::" -Right " - "
          $row.Namespace = FindSep -FindIn $part -Left ($row.Operation + " - ") -Right " : "
          $row.Query = FindSep -FindIn $part -Left ($row.Namespace + " : ") -Right ";"
          $row.ClientMachine = FindSep -FindIn $part -Left "ClientMachine = " -Right ";"
          $row.User = FindSep -FindIn $part -Left "User = " -Right ";"
          $row.ClientPID = FindSep -FindIn $part -Left "ClientProcessId = " -Right ";"
          $tbEvt.Rows.Add($row)
        }
      }
    } else {
      if ($part -match  "Stop OperationId") {        
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
    }
  }

  if ($line -match  "\[Microsoft-Windows-WMI-Activity/Operational\]") {
    $npos=$line.IndexOf("::")
    $time = ($line.Substring($nPos + 2 , 25))
    $part = $line
    $line = $sr.ReadLine()
    if ($line.substring(0,1) -ne "[" ) {
      $part = $part + $line
    }
    $CorrelationID = FindSep -FindIn $part -Left "Id = " -Right ";"
    if ($CorrelationID -eq "") {
      Write-Host "Provider started"
    } else { 
      Write-Host $part
      $Operation = FindSep -FindIn $part -Left "Operation = " -Right " - "
      $NameSpace = FindSep -FindIn $part -Left ($Operation + " - ") -Right " : "
      $Query = (FindSep -FindIn $part -Left ($NameSpace + " : ")  -Right ";").Replace("'","''")
      
      $select  = "CorrelationID = '" + $CorrelationID + "' and Query = '" + $query + "'"
      $aOpId = $tbEvt.Select($select)
      if ($aOpId.Count -gt 0) { 
        $item = $aOpId.Count - 1
        $ResultCode = FindSep -FindIn $part -Left "ResultCode = " -Right ";"

        $dtStart = ToTime $aOpId[0].Time
        $dtEnd = ToTime $time
        $duration = New-TimeSpan -Start $dtStart -End $dtEnd
          
        $aOpId[$item].ResultCode = $ResultCode
        $aOpId[$item].Duration = $duration.TotalMilliseconds
      }
    }
    Write-Host $part
  }
  if ($part -eq "") {
    $line = $sr.ReadLine()
  }
}

$sr.Close()

$tbEvt | Export-Csv ($FileName + ".csv") -noType

$duration = New-TimeSpan -Start $dtInit -End (Get-Date)
Write-Host "Execution completed in" $duration.TotalSeconds "seconds"
