# DecodeDCOMEvents - by Gianni Bragante gbrag@microsoft.com
# Version 20211231

param (
  [string]$InputFile, 
  [int32] $Max = 5000
)

Function FindGUIDs {
  param (
    [string]$msg
  )
  $msg = $msg.Replace("`r`n", " ")
  $msgres = $msg
  $start = 0
  $guidres = ""

  $pos = $msg.IndexOf("{") 
  while ($pos -gt 0) {
    $pos += $start
    $end = $msg.substring($pos).IndexOf("}") + 1
    $guid = $msg.Substring($pos, $end)
    if ($guidres.IndexOf($guid) -eq -1) {
      if ($guidCache[$guid] ) {
        $guidexp = $guidCache[$guid]
      } else {
        $guidexp = $guid + " (" + (DecodeGUID $guid) + ")"
        $guidCache.Add($guid,$guidexp)
      }

      $msgres = $msgres.Replace($guid, $guidexp)
      $guidres += $guid  # this will prevent replacing the same GUID again in the same message
    }
    $start = $pos + $end
    $pos = $msg.substring($start).IndexOf("{")
  }
  return $msgres
}

Function DecodeGUID {
  param (
    [string]$GUID
  )
  $reg = Get-ItemProperty ("HKLM:\SOFTWARE\Classes\CLSID\" + $GUID) -ErrorAction SilentlyContinue
  if ($reg) {
    return $reg.'(default)'
  } else {
    $reg = Get-ItemProperty ("HKLM:\SOFTWARE\Classes\AppID\" + $GUID) -ErrorAction SilentlyContinue
    if ($reg) {
      if ($reg.'(default)') {
        return $reg.'(default)'
      } elseif ($reg.LocalService) {
        return ($reg.LocalService)
      } else {
        return "Unknown"
      }
    } else {
      return "Unknown"
    }
  }
}

if (-not $InputFile) {
  Write-Host "Please specify a file name"
  exit
} 

if (Test-Path $InputFile) {
  $Path = (Get-Item -Path $InputFile).FullName
} else {
  Write-Host "$InputFile does not exist"
  exit
}

$guidCache = @{}


Write-Host "Parsing the file $Path"

$events = Get-WinEvent -Path $Path -MaxEvents 1 -Oldest

$querytime = $events[0].TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$prevtime = $events[0].TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$query = ("<QueryList><Query Id=""0"" Path=""file://$Path""><Select Path=""file://$Path"">*[System[Provider[@Name='Microsoft-Windows-DistributedCOM'] and TimeCreated[@SystemTime&gt;='" + $querytime + "']]]</Select></Query></QueryList>")
$events = Get-WinEvent -Path $Path -FilterXPath $query -MaxEvents $max -ErrorAction SilentlyContinue

if (-not $events) {
  Write-Host "No DCOM events in the specified file"
  exit
}

$root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path 
$outfile = $Inputfile + ".dcom.csv"
"Date,Level,ID,Message" | Out-File -FilePath $outfile -Force

while ($events) {
  foreach ($evt in $events) {
    $res = FindGUIDs $evt.Message
    $csvline = ($evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") + "," + $evt.LevelDisplayName + "," + $evt.id + "," + $res)
    Write-Host $csvline
    $csvline | Out-File -FilePath $outfile -Append
    # Write-host ""
  }
  $querytime = $evt.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
  $query = ("<QueryList><Query Id=""0"" Path=""file://$Path""><Select Path=""file://$Path"">*[System[Provider[@Name='Microsoft-Windows-DistributedCOM'] and TimeCreated[@SystemTime&gt;='" + $time + "']]]</Select></Query></QueryList>")
  $events = Get-WinEvent -Path $Path -FilterXPath $query -MaxEvents $max -Oldest -ErrorAction SilentlyContinue
}