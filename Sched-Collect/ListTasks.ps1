Function DecodeResult ($res) {
  switch ($res) {
    267009 { return "The task is currently running"}
    267011 { return "The task has not yet run"}
    267011 { return "The task has not yet run"}
  }
}

$tbTasks = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Path,([string]); $tbTasks.Columns.Add($col)
$col = New-Object system.Data.DataColumn Name,([string]); $tbTasks.Columns.Add($col)
$col = New-Object system.Data.DataColumn Enabled,([boolean]); $tbTasks.Columns.Add($col)
$col = New-Object system.Data.DataColumn State,([string]); $tbTasks.Columns.Add($col)
$col = New-Object system.Data.DataColumn LastRunTime,([string]); $tbTasks.Columns.Add($col)
$col = New-Object system.Data.DataColumn LastResult,([string]); $tbTasks.Columns.Add($col)
$col = New-Object system.Data.DataColumn NextRunTime,([string]); $tbTasks.Columns.Add($col)
$col = New-Object system.Data.DataColumn Maintenance,([string]); $tbTasks.Columns.Add($col)

$tasks = Get-ScheduledTask
foreach ($task in $tasks) {
  $info = Get-ScheduledTaskInfo $task
  $row = $tbTasks.NewRow()
  $row.Path = $task.TaskPath
  $row.Name = $task.TaskName
  $row.Enabled = $task.Settings.Enabled
  $row.State = $task.State
  $row.LastRunTime = $info.LastRunTime
  $row.LastResult = ( $info.LastTaskResult.ToString() + " " + (DecodeResult $info.LastTaskResult))
  $row.NextRunTime = $info.NextRunTime
  if ($task.Settings.MaintenanceSettings) {
    $row.Maintenance = "Yes" 
  } else {
    $row.Maintenance = "No" 
  } 
  $tbTasks.Rows.Add($row)
  Write-host $task.TaskName $task.Settings.MaintenanceSettings
}
$tbTasks | Export-Csv "tasks.csv"