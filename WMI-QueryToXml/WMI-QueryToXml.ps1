param( [string]$Query, [string]$NameSpace)

$version = "WMI-QueryToXml (20180705)"
# by Gianni Bragante - gbrag@microsoft.com

$Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path
$resName = "WMI-QueryToXml-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmssfff)
$resDir = $Root + "\" + $resName
New-Item -itemtype directory -path $resDir | Out-Null

$tbRes = New-Object system.Data.DataTable “evt”
$col = New-Object system.Data.DataColumn Num,([string])
$tbRes.Columns.Add($col)
$col = New-Object system.Data.DataColumn Name,([string])
$tbRes.Columns.Add($col)

$num = 0
$result = Get-CimInstance -Query $Query -Namespace $NameSpace
foreach ($instance in $result) {
  $instance | ConvertTo-Xml | Export-Clixml -Path ($resDir + "\" + ($num).ToString() + ".xml")

  $row = $tbRes.NewRow()
  $row.Num = $num.ToString()
  $row.Name = $instance.Name
  $tbRes.Rows.Add($row)

  $num++
}
$tbRes| Export-Csv ($resDir + "\results.csv") -noType
$query | Out-File -FilePath ($resDir + "\query.txt") -Append -Encoding ascii
$namespace | Out-File -FilePath ($resDir + "\query.txt") -Append -Encoding ascii
