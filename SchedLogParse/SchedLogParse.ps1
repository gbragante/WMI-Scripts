param (
  [string] $FilePath, [int32] $Max = 50
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

if (-not $FilePath) {
  Write-Host "Please specify a file name"
} 

if (Test-Path $FilePath) {
  $Path = (Get-Item -Path $FilePath).FullName
} else {
  Write-Host "$FilePath does not exist"
  exit
}

$tbEvt = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Time,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Event,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Id,([int32]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Level,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Task,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Action,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Instance,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn User,([string]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn PID,([int32]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Priority,([int32]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn ReturnCode,([int64]); $tbEvt.Columns.Add($col)
$col = New-Object system.Data.DataColumn Text,([string]); $tbEvt.Columns.Add($col)

$root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path 
$outfile = $root + "\Events-" + $env:computername +"-" + (Get-date).ToString("yyyyMMdd-HHmmss") + ".csv"
Write-Host "Parsing the file $Path"

$events = Get-WinEvent -Path $Path -MaxEvents 1 -Oldest
$querytime = $events[0].TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
#$prevtime = $events[0].TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$prevtime = $querytime

$query = ("<QueryList><Query Id=""0"" Path=""file://$Path""><Select Path=""file://$Path"">*[System[TimeCreated[@SystemTime&gt;='" + $querytime + "']]]</Select></Query></QueryList>")
$events = Get-WinEvent -Path $Path -FilterXPath $query -MaxEvents $max -Oldest

while ($events) {
  foreach ($evt in $events) {
    $time = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.fff")
    $xmlEvt = New-Object -TypeName System.Xml.XmlDocument
    $xmlEvt.LoadXml($evt.ToXml())
    $row = $tbEvt.NewRow()
    $row.Time = $time
    $row.Id = $evt.Id
    $row.Level = $evt.LevelDisplayName
    $row.text = $evt.Message

    Write-Host ($time + " " + $evt.Id)

    if ($evt.Id -eq 100) { # Task Started
      $row.Event = "Task Started"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[2].'#text'
      $row.User = $xmlEvt.Event.EventData.Data[1].'#text'
    } elseif ($evt.Id -eq 200) {
      $row.Event = "Action started"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[2].'#text'
      $row.Action = $xmlEvt.Event.EventData.Data[1].'#text'
    } elseif ($evt.Id -eq 107) {
      $row.Event = "Task triggered on scheduler"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[1].'#text'
    } elseif ($evt.Id -eq 129) {
      $row.Event = "Created Task Process"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Action = $xmlEvt.Event.EventData.Data[1].'#text'
      $row.PID = $xmlEvt.Event.EventData.Data[2].'#text'
      $row.Priority = $xmlEvt.Event.EventData.Data[3].'#text'
    } elseif ($evt.Id -eq 201) {
      $row.Event = "Action completed"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[1].'#text'
      $row.Action = $xmlEvt.Event.EventData.Data[2].'#text'
      $row.ReturnCode = $xmlEvt.Event.EventData.Data[3].'#text'
    } elseif ($evt.Id -eq 102) {
      $row.Event = "Task completed"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.User = $xmlEvt.Event.EventData.Data[1].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[2].'#text'
    } elseif ($evt.Id -eq 140) {
      $row.Event = "Task registration updated"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.User = $xmlEvt.Event.EventData.Data[1].'#text'
    } elseif ($evt.Id -eq 118) {
      $row.Event = "Task triggered by computer startup"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[1].'#text'
    } elseif ($evt.Id -eq 141) {
      $row.Event = "Task registration deleted"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.User = $xmlEvt.Event.EventData.Data[1].'#text'
    } elseif ($evt.Id -eq 111) {
      $row.Event = "Task terminated"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[1].'#text'
    } elseif ($evt.Id -eq 106) {
      $row.Event = "Task registered"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.User = $xmlEvt.Event.EventData.Data[1].'#text'
    } elseif ($evt.Id -eq 202) {
      $row.Event = "Action failed"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[1].'#text'
      $row.Action = $xmlEvt.Event.EventData.Data[2].'#text'
      $row.ReturnCode = $xmlEvt.Event.EventData.Data[3].'#text'
    } elseif ($evt.Id -eq 103) {
      $row.Event = "Action start failed"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[1].'#text'
      $row.User = $xmlEvt.Event.EventData.Data[2].'#text'
      $row.ReturnCode = $xmlEvt.Event.EventData.Data[3].'#text'
    } elseif ($evt.Id -eq 142) {
      $row.Event = "Task disabled"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.User = $xmlEvt.Event.EventData.Data[1].'#text'
    } elseif ($evt.Id -eq 402) {
      $row.Event = "Service is shutting down"
    } elseif ($evt.Id -eq 700) {
      $row.Event = "Compatibility module started"
    } elseif ($evt.Id -eq 400) {
      $row.Event = "Service started"
    } elseif ($evt.Id -eq 101) {
      $row.Event = "Task Start Failed"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.User = $xmlEvt.Event.EventData.Data[1].'#text'
      $row.ReturnCode = $xmlEvt.Event.EventData.Data[2].'#text'
    } elseif ($evt.Id -eq 325) {
      $row.Event = "Launch request queued"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[1].'#text'
    } elseif ($evt.Id -eq 110) {
      $row.Event = "Task triggered by user"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[1].'#text'
      $row.User = $xmlEvt.Event.EventData.Data[2].'#text'
    } elseif ($evt.Id -eq 108) {
      $row.Event = "Task triggered on event"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[1].'#text'
    } elseif ($evt.Id -eq 114) {
      $row.Event = "Missed task started"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[1].'#text'
    } elseif ($evt.Id -eq 322) {
      $row.Event = "Launch request ignored, instance already running"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[1].'#text'
    } elseif ($evt.Id -eq 119) {
      $row.Event = "Task triggered on logon"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.User = $xmlEvt.Event.EventData.Data[1].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[2].'#text'
    } elseif ($evt.Id -eq 329) {
      $row.Event = "Task stopping due to timeout reached"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[1].'#text'
    } elseif ($evt.Id -eq 153) {
      $row.Event = "Missed task start rejected"
      $row.Task = $xmlEvt.Event.EventData.Data.'#text'
    } elseif ($evt.Id -eq 332) {
      $row.Event = "Launch condition not met, user not logged-on"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.User = $xmlEvt.Event.EventData.Data[1].'#text'
    } elseif ($evt.Id -eq 330) {
      $row.Event = "Task stopping due to user request"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[1].'#text'
      $row.User = $xmlEvt.Event.EventData.Data[2].'#text'
    } elseif ($evt.Id -eq 109) {
      $row.Event = "Task triggered by registration"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[1].'#text'
    } elseif ($evt.Id -eq 324) {
      $row.Event = "Launch request queued, instance already running"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[1].'#text'
      $row.Action = ("Running instance: " + $xmlEvt.Event.EventData.Data[2].'#text')
    } elseif ($evt.Id -eq 203) {
      $row.Event = "Action failed to start"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[1].'#text'
      $row.Action = $xmlEvt.Event.EventData.Data[2].'#text'
      $row.ReturnCode = $xmlEvt.Event.EventData.Data[3].'#text'
    } elseif ($evt.Id -eq 113) {
      $row.Event = "Task registered without some triggers"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.ReturnCode = $xmlEvt.Event.EventData.Data[1].'#text'
    } elseif ($evt.Id -eq 150) {
      $row.Event = "Task registration on event failed"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.ReturnCode = $xmlEvt.Event.EventData.Data[1].'#text'
    } elseif ($evt.Id -eq 411) {
      $row.Event = "Service signaled time change"
    } elseif ($evt.Id -eq 328) {
      $row.Event = "Task stopping due to computer not idle"
      $row.Task = $xmlEvt.Event.EventData.Data[0].'#text'
      $row.Instance = $xmlEvt.Event.EventData.Data[1].'#text'
    } else {
      Write-Host
    }
    $tbEvt.Rows.Add($row)
  }
  $prevtime = $querytime
  $querytime = $evt.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
  $query = ("<QueryList><Query Id=""0"" Path=""file://$Path""><Select Path=""file://$Path"">*[System[TimeCreated[@SystemTime&gt;='" + $querytime + "']]]</Select></Query></QueryList>")
  $events = Get-WinEvent -Path $Path -FilterXPath $query -MaxEvents $max -Oldest -ErrorAction SilentlyContinue
  if ($prevtime -eq $querytime) {
    break
  }
}

Write-Host "Exporting Scheduler events to csv"
$tbEvt | Export-Csv ($FilePath + ".csv") -noType