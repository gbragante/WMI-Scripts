# WMI-TraceParse - 20180209
# by Gianni Bragante - gbrag@microsoft.com

param (
  [string]$FileName
)

Function FindSep {
  param( [string]$FindIn, [string]$Left,[string]$Right )
  $Start = $FindIn.IndexOf($Left) + $Left.Length
  if ($Right -eq "") {
    $End = $FindIn.Substring($Start).Length
  } else {
    $End = $FindIn.Substring($Start).IndexOf($Right)
  }
  $Found = $FindIn.Substring($Start, $End)
  return $Found
}

Function ToTime{
  param( [string]$time)
  return Get-Date -Year $time.Substring(6,2) -Month $time.Substring(0,2) -Day $time.Substring(3,2) -Hour $time.Substring(9,2) -Minute $time.Substring(12,2) -Second $time.Substring(15,2) -Millisecond $time.Substring(18,3)
}

#$FileName = ".\Trace-Spike.txt"
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

$dtStart = Get-Date

$sr = new-object System.io.streamreader(get-item $FileName)
$line = $sr.ReadLine()
$lines = $lines + 1
while (-not $sr.EndOfStream) {
  if ($line -match  "\[Microsoft-Windows-WMI-Activity/Trace\]") {
    
    $npos=$line.IndexOf("::")
    $time = ($line.Substring($nPos + 2 , 25))

    if ($line -match  "CorrelationId =") {  
      if ($line -match  "Protocol = DCOM") {
      } else {
        if ($line -match  "::Connect") {
        } else {    
          $row = $tbEvt.NewRow()
          $row.Time = $time
          $row.CorrelationID = FindSep -FindIn $line -Left "CorrelationId = " -Right ";"
          $row.GroupOperationID = FindSep -FindIn $line -Left "GroupOperationId = " -Right ";"
          $row.OperationID = FindSep -FindIn $line -Left " OperationId = " -Right ";"
          $row.Operation = FindSep -FindIn $line -Left "Start IWbemServices::" -Right " - "
          $row.Namespace = FindSep -FindIn $line -Left ($row.Operation + " - ") -Right " : "
          $row.Query = FindSep -FindIn $line -Left ($row.Namespace + " : ") -Right ";"
          $row.ClientMachine = FindSep -FindIn $line -Left "ClientMachine = " -Right ";"
          $row.User = FindSep -FindIn $line -Left "User = " -Right ";"
          $row.ClientPID = FindSep -FindIn $line -Left "ClientProcessId = " -Right ";"
          $tbEvt.Rows.Add($row)
        }
      }
    } else {
      if ($line -match  "Stop OperationId") {        
        $OperationID = FindSep -FindIn $line -Left "OperationId = " -Right ";"     
        $aOpId = $tbEvt.Select("OperationID = '" + $OperationID + "'")
        
        if ($aOpId.Count -gt 0) { 
          $ResultCode = FindSep -FindIn $line -Left "ResultCode = " -Right ""

          $dtStart = ToTime $aOpId[0].Time
          $dtEnd = ToTime $time
          $duration = New-TimeSpan -Start $dtStart -End $dtEnd
          
          $aOpId[0].ResultCode = $ResultCode
          $aOpId[0].Duration = $duration.TotalMilliseconds
        }
      }
    }
  }
  $line = $sr.ReadLine()
}

$sr.Close()

$tbEvt | Export-Csv ($FileName + ".csv") -noType

$duration = New-TimeSpan -Start $dtStart -End (Get-Date)
Write-Host "Execution completed in" $duration