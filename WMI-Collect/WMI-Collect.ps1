param( [string]$DataPath, `
       [switch]$AcceptEula, `
       [switch]$Logs, `
       [switch]$Trace, `
       [switch]$Activity, `
       [switch]$Storage, `
       [switch]$Cluster, `
       [switch]$DCOM, `
       [switch]$RPC, `
       [switch]$MDM, `
       [switch]$Perf, `
       [switch]$RDMS, `
       [switch]$RDSPub, `
       [switch]$SCM, `
       [switch]$PerfMonWMIPrvSE, `
       [switch]$Network, `
       [switch]$WPR, `
       [switch]$Kernel
     )

$version = "WMI-Collect (20240530)"
# by Gianni Bragante - gbrag@microsoft.com

$DiagVersion = "WMI-RPC-DCOM-Diag (20230309)"
# by Marius Porcolean maporcol@microsoft.com

Function GetOwnerCim{
  param( $prc )
  $ret = Invoke-CimMethod -InputObject $prc -MethodName GetOwner
  return ($ret.Domain + "\" + $ret.User)
}

Function GetOwnerWmi{
  param( $prc )
  $ret = $prc.GetOwner()
  return ($ret.Domain + "\" + $ret.User)
}

Function Write-LogMessage {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Message,

        [Parameter()]
        [ValidateSet('Error', 'Warning', 'Pass', 'Info')]
        [string] $Type = $null
    )
    
    $Color = $null
    switch ($Type) {
        "Error" {
            $Message = (Get-Date).ToString("yyyyMMdd-HH:mm:ss.fff") + "    " + "[ERROR]   " + $Message
            $Color = 'Magenta'
        }
        "Warning" {
            $Message = (Get-Date).ToString("yyyyMMdd-HH:mm:ss.fff") + "    " + "[WARNING] " + $Message
            $Color = 'Yellow'
        }
        "Pass" {
            $Message = (Get-Date).ToString("yyyyMMdd-HH:mm:ss.fff") + "    " + "[PASS]    " + $Message
            $Color = 'Green'
        }
        Default {
            $Message = (Get-Date).ToString("yyyyMMdd-HH:mm:ss.fff") + "    " + "[INFO]    " + $Message
        }
    }
    if ([string]::IsNullOrEmpty($Color)) {
        Write-Host $Message
    } 
    else {
        Write-Host $Message -ForegroundColor $Color
    }
    if (!($NoLogFile)) {
        $Message | Out-File -FilePath $diagfile -Append
    }
}

Function WMITraceCapture {
  $cmd =  ("logman create trace 'wmi-trace' -ow -o '" + $TracesDir + "WMI-Trace-$env:COMPUTERNAME.etl" + "' -p 'Microsoft-Windows-WMI' 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets")
  Write-Log $cmd
  while ($true) {
    $out = Invoke-Expression $cmd
    if ($out -match "Error") {
      Write-Log ("Waiting for the WMI etw provider to become available" + $out)
      Sleep 1
    } else {
      Write-Log "Trace created"
      break
    }
  }

  if (((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber) -ge 26063) {
    $cmd = "winmgmt /dumptasks arb 1 LogFile:""" + $TracesDir + "WMI-Trace-$env:COMPUTERNAME.arb.txt""" + $RdrErr
    Write-Log $cmd
    $scriptBlock = {
      Invoke-Expression ($using:cmd)
    }
    Write-Log "Submitting ArbDumpJob"
    $job = Start-Job -Name "ArbDumpJob" -ScriptBlock $scriptBlock -ArgumentList $cmd
  }

  Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}' 0xffffffffffffffff 0xff -ets" # WMI-Activity

  if (-not $Activity) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{2CF953C0-8DF7-48E1-99B9-6816A2FBDC9F}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-WMIAdapter
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{1FF6B227-2CA7-40F9-9A66-980EADAA602E}' 0xffffffffffffffff 0xff -ets" # WMI_Tracing
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{8E6B6962-AB54-4335-8229-3255B919DD0E}' 0xffffffffffffffff 0xff -ets" # WMI_Tracing_Client_Operations_Info_Guid
  }
  if ($Storage) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{595F33EA-D4AF-4F4D-B4DD-9DACDD17FC6E}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-StorageManagement-WSP-Host
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{88C09888-118D-48FC-8863-E1C6D39CA4DF}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-StorageManagement-WSP-Spaces
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{C6281CF0-7253-4185-9A91-486327931BDC}' 0xffffffffffffffff 0xff -ets" # SxControlGuid
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{9282168F-2432-45F0-B91C-3AF363C149DD}' 0xffffffffffffffff 0xff -ets" # TRACELOG_PROVIDER_NAME_STORAGEWMI
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{7E58E69A-E361-4F06-B880-AD2F4B64C944}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-StorageManagement
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{88B892C2-FCCD-4881-946A-032897F954B0}' 0xffffffffffffffff 0xff -ets" # Provider Passthru
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{E14DCDD9-D1EC-4DC3-8395-A606DF8EF115}' 0xffffffffffffffff 0xff -ets" # virtdisk
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{4D20DF22-E177-4514-A369-F1759FEEDEB3}' 0xffffffffffffffff 0xff -ets" # virtdisk
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{C24D82FA-8E22-46C8-9D79-4D763EA059D0}' 0xffffffffffffffff 0xff -ets" # storagewmi
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{80DF111F-178D-44FB-AFB4-5D179DE9D4EC}' 0xffffffffffffffff 0xff -ets" # storagewmi
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{4FA1102E-CC1D-4509-A69F-121E2CC96F9C}' 0xffffffffffffffff 0xff -ets" # SDDC
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{7F8DA3B5-A58F-481E-9637-D41435AE6D8B}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-SDDC-Management
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{6D09BA4F-D4D0-49DD-8BDD-DEB59A33DFA8}' 0xffffffffffffffff 0xff -ets" # TRACELOG_PROVIDER_NAME_SMPHOST
  }
  
  if ($Cluster) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{0461BE3C-BC15-4BAD-9A9E-51F3FADFEC75}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-FailoverClustering-WMIProvider
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{FF3E7036-643F-430F-B015-2933466FF0FD}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-FailoverClustering-WMI
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{D82DBA12-8B70-49EE-B844-44D0885951D2}' 0xffffffffffffffff 0xff -ets" # CSVFLT
  }  
  if ($DCOM) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{B46FA1AD-B22D-4362-B072-9F5BA07B046D}' 0xffffffffffffffff 0xff -ets" # comsvcs
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{A0C4702B-51F7-4ea9-9C74-E39952C694B8}' 0xffffffffffffffff 0xff -ets" # comadmin
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{9474a749-a98d-4f52-9f45-5b20247e4f01}' 0xffffffffffffffff 0xff -ets" # dcomscm
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{bda92ae8-9f11-4d49-ba1d-a4c2abca692e}' 0xffffffffffffffff 0xff -ets" # ole32
    Invoke-CustomCommand "reg add HKEY_LOCAL_MACHINE\Software\Microsoft\OLE\Tracing /v ExecutablesToTrace /t REG_MULTI_SZ /d * /f"
  }  
  if ($RPC) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{6AD52B32-D609-4BE9-AE07-CE8DAE937E39}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-RPC
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{F4AED7C7-A898-4627-B053-44A7CAA12FCD}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-RPC-Events
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{D8975F88-7DDB-4ED0-91BF-3ADF48C48E0C}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-RPCSS
  }  
  if ($MDM) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{0A8E17FD-ED19-4C54-A1E7-5A2829BF507F}' 0xffffffffffffffff 0xff -ets" # DMCmnUtils
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{F1201B5A-E170-42B6-8D20-B57AC57E6416}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-DeviceManagement-Pushrouter
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{9FBF7B95-0697-4935-ADA2-887BE9DF12BC}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-DM-Enrollment-Provider
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{3DA494E4-0FE2-415C-B895-FB5265C5C83B}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{E74EFD1A-B62D-4B83-AB00-66F4A166A2D3}' 0xffffffffffffffff 0xff -ets" # Microsoft.Windows.EMPS.Enrollment
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{F9E3B648-9AF1-4DC3-9A8E-BF42C0FBCE9A}' 0xffffffffffffffff 0xff -ets" # Microsoft.Windows.EnterpriseManagement.Enrollment
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{86625C04-72E1-4D36-9C86-CA142FD0A946}' 0xffffffffffffffff 0xff -ets" # Microsoft.Windows.DeviceManagement.OmaDmApiProvider
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{7D85C2D0-6490-4BB4-BAC1-247D0BD06F10}' 0xffffffffffffffff 0xff -ets" # Microsoft-WindowsPhone-OMADMAPI-Provider
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{EF614386-F019-4323-85A1-D6EBAF9CDE12}' 0xffffffffffffffff 0xff -ets" # WPPCtrlGuid
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{A76DBA2C-9683-4BA7-8FE4-C82601E117BB}' 0xffffffffffffffff 0xff -ets" # WMIBRIDGE_TRACE_LOGGING_PROVIDER
  }  
  if ($Perf) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{BFFB9DBD-5983-4197-BB1A-243798DDBEC7}' 0xffffffffffffffff 0xff -ets" # WMIPerfClass
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{970406AD-6475-45DA-AA30-57E0037770E4}' 0xffffffffffffffff 0xff -ets" # WMIPerfInst	
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{62841F33-387A-4674-94A4-485C418C57EE}' 0xffffffffffffffff 0xff -ets" # Pdh
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{04D66358-C4A1-419B-8023-23B73902DE2C}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-PDH
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{E1A5FA6F-2E74-4C70-B292-D34C4338D54C}' 0xffffffffffffffff 0xff -ets" # LoadperfDll
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{BC44FFCD-964B-5B85-8662-0BA87EDAF07A}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Perflib
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{13B197BD-7CEE-4B4E-8DD0-59314CE374CE}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Perflib
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{970407AD-6485-45DA-AA30-58E0037770E4}' 0xffffffffffffffff 0xff -ets" # PerfLib
  }  
  if ($RDMS) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{FB750AD9-8544-427F-B284-8ED9C6C221AE}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Rdms-UI
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{05DA6B40-219E-4F17-92E6-D663FD87CBA8}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Remote-Desktop-Management-Service
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{1B9B72FC-678A-41C1-9365-824658F887E9}' 0xffffffffffffffff 0xff -ets" # RDMSTrace
  }  
  if ($RDSPub) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{81B84BCE-06B4-40AE-9840-8F04DD7A8DF7}' 0xffffffffffffffff 0xff -ets" # TSCPubWmiProvider
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{0CEA2AEE-1A4C-4DE7-B11F-161F3BE94669}' 0xffffffffffffffff 0xff -ets" # TSPublishingIconHelperTrace
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{1B9B72FC-678A-41C1-9365-824658F887E9}' 0xffffffffffffffff 0xff -ets" # TSPublishingAppFilteringTrace
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{7ADA0B31-F4C2-43F4-9566-2EBDD3A6B604}' 0xffffffffffffffff 0xff -ets" # TSCentralPublishingTrace
  }  
  if ($SCM) {
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{EBCCA1C2-AB46-4A1D-8C2A-906C2FF25F39}' 0xffffffffffffffff 0xff -ets" # ScReg
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{0063715B-EEDA-4007-9429-AD526F62696E}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Services
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{06184C97-5201-480E-92AF-3A3626C5B140}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Services-Svchost
    Invoke-CustomCommand "logman update trace 'wmi-trace' -p '{555908D1-A6D7-4695-8E1E-26931D2012F4}' 0xffffffffffffffff 0xff -ets" # Service Control Manager
  }  
  if ($PerfMonWMIPrvSE) {
    #Invoke-CustomCommand ("Logman create counter 'WMI-Trace-PerfMonWMIPrvSE' -f bincirc -max 512 -c '\WMIPrvSE Health Status(*)\*' -si 00:00:01 -o '" + $TracesDir + "WMI-Trace-PerfMonWMIPrvSE-$env:COMPUTERNAME.blg'")
    $utcOffset = ((Get-Date) - (Get-Date).ToUniversalTime()).TotalMinutes
    $sign = if ($utcOffset -ge 0) { '+' } else { '-' }
    $utcOffset = [Math]::Abs($utcOffset)
    $utcOffset = '-TZ{0}{1:000}' -f $sign, $utcOffset

    Invoke-CustomCommand ("Logman create counter 'WMI-Trace-PerfMonWMIPrvSE' -f bincirc -max 512 -c '\Process(WmiPrvSE*)\ID Process' '\Process(WmiPrvSE*)\Thread Count' '\Process(WmiPrvSE*)\Handle Count' '\Process(WmiPrvSE*)\Working Set' '\Process(WmiPrvSE*)\% Processor Time' -si 00:00:01 -o '" + $TracesDir + "WMI-Trace-PerfMonWMIPrvSE-$env:COMPUTERNAME$utcOffset.blg' -ow --v")
    Invoke-CustomCommand ("logman start 'WMI-Trace-PerfMonWMIPrvSE'")
  }

  if ($Network) {
    Invoke-CustomCommand ("netsh trace start capture=yes scenario=netconnection maxsize=2048 report=disabled tracefile='" + $TracesDir + "NETCAP-" + $env:COMPUTERNAME + ".etl'")
  }  
  if ($Kernel) {
    Invoke-CustomCommand ("logman create trace 'NT Kernel Logger' -ow -o '" + $TracesDir + "WMI-Trace-kernel-$env:COMPUTERNAME.etl" + "' -p '{9E814AAD-3204-11D2-9A82-006008A86939}' 0x1 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 512 -ets")
  }
  if ($WPR) {
    Invoke-CustomCommand ("wpr -start GeneralProfile -start CPU")
  }

  Write-Log "Trace capture started"
  read-host "Press ENTER to stop the capture"
  Invoke-CustomCommand "logman stop 'wmi-trace' -ets"
  
  if ($DCOM) {
    Invoke-CustomCommand "reg delete HKEY_LOCAL_MACHINE\Software\Microsoft\OLE\Tracing /v ExecutablesToTrace /f"
  }  
  if ($PerfMonWMIPrvSE) {
    Invoke-CustomCommand ("logman stop 'WMI-Trace-PerfMonWMIPrvSE'")
    Invoke-CustomCommand ("logman delete 'WMI-Trace-PerfMonWMIPrvSE'")
  }
  if ($Network) {
    Invoke-CustomCommand "netsh trace stop"
  }  
  if ($Kernel) {
    Invoke-CustomCommand "logman stop 'NT Kernel Logger' -ets"
  }  
  Invoke-CustomCommand "tasklist /svc" -DestinationFile "Traces\tasklist-$env:COMPUTERNAME.txt"
  if ($WPR) {
    Invoke-CustomCommand ("wpr -stop '"+ $TracesDir + $env:COMPUTERNAME + "_GenProf.etl'")
  }

  if (((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber) -ge 26063) {
    Write-Log "Ensuring ArbDumpJob is no longer running"
    Wait-Job -Name "ArbDumpJob"| Out-Null
  }
}

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

$global:Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path
$resName = "WMI-Results-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)

if ($DataPath) {
  if (-not (Test-Path $DataPath)) {
    Write-Host "The folder $DataPath does not exist"
    exit
  }
  $global:resDir = $DataPath + "\" + $resName
} else {
  $global:resDir = $global:Root + "\" + $resName
}

try {
  Import-Module ($global:Root + "\Collect-Commons.psm1") -Force -DisableNameChecking -ErrorAction Stop
}
catch {
  Write-Host "Unable to import the helper module, can't continue without it! Exiting..." -ForegroundColor Red
  Write-Host ($_.Exception.Message) -ForegroundColor Red
  exit
}

if (-not $Trace -and -not $Logs) {
    Write-Host "$version, a data collection tool for WMI troubleshooting"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "WMI-Collect -Logs"
    Write-Host "  Collects dumps, logs, registry keys, command outputs"
    Write-Host ""
    Write-Host "WMI-Collect -Trace [-Activity][-Storage][-Cluster][-DCOM][-RPC][-MDM][-RDMS][-RDSPUB][-Network][-Kernel][-WPR]"
    Write-Host "  Collects live trace"
    Write-Host ""
    Write-Host "WMI-Collect -Logs -Trace [-Activity][-Storage][-Cluster][-DCOM][-RPC][-MDM][-RDMS][-RDSPub][-Network][-Kernel][-WPR]"
    Write-Host "  Collects live trace then -Logs data"
    Write-Host ""
    Write-Host "Parameters for -Trace :"
    Write-Host "  -Activity : Only trace WMI-Activity, less detailed"
    Write-Host "  -Storage : Storage providers"
    Write-Host "  -Cluster : Cluster providers"
    Write-Host "  -DCOM : OLE, COM and DCOM tracing"
    Write-Host "  -RPC : Remote Procedure Call"
    Write-Host "  -MDM : Mobile Device Manager"
    Write-Host "  -Perf : WMIPerfClass, WMIPerfInst, PDH and PerfLib"
    Write-Host "  -RDMS : Remote Desktop Management"
    Write-Host "  -RDSPub : Remote Desktop Publishing"
    Write-Host "  -Network : Network capture"
    Write-Host "  -Kernel : Kernel Trace for process start and stop"
    Write-Host "  -WPR: Windows Performance Recorder trace (GeneralProfile CPU)"
    Write-Host "  -PerfMonWMIPrvSE: Performance monitor data for WMIPrvSE processes"
    Write-Host ""
    exit
}

New-Item -itemtype directory -path $global:resDir | Out-Null

$global:outfile = $global:resDir + "\script-output.txt"
$global:errfile = $global:resDir + "\script-errors.txt"
$diagfile = $global:resDir + "\WMI-RPC-DCOM-Diag.txt"

Write-Log $version
if ($AcceptEula) {
  Write-Log "AcceptEula switch specified, silently continuing"
  $eulaAccepted = ShowEULAIfNeeded "WMI-Collect" 2
} else {
  $eulaAccepted = ShowEULAIfNeeded "WMI-Collect" 0
  if($eulaAccepted -ne "Yes")
   {
     Write-Log "EULA declined, exiting"
     exit
   }
 }
Write-Log "EULA accepted, continuing"
Write-Log ("Command line : " + $MyInvocation.Line)

if ($Trace) {
  $TracesDir = $global:resDir + "\Traces\"
  New-Item -itemtype directory -path $TracesDir | Out-Null
  WMITraceCapture
  if (-not $Logs) {
    exit
  }
}

$subDir = $global:resDir + "\Subscriptions"
New-Item -itemtype directory -path $subDir | Out-Null

Write-Log "Collecting dump of the svchost process hosting the WinMgmt service"
$pidsvc = FindServicePid "winmgmt"
if ($pidsvc) {
  Write-Log "Found the PID using FindServicePid"
  CreateProcDump $pidsvc $global:resDir "svchost-WinMgmt"
} else {
  Write-Log "Cannot find the PID using FindServicePid, looping through processes"
  $list = Get-Process
  $found = $false
  if (($list | Measure-Object ).count -gt 0) {
    foreach ($proc in $list) {
      $prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "wmisvc.dll"} 
      if (($prov | Measure-Object).count -gt 0) {
        Write-Log "Found the PID having wmisvc.dll loaded"
        CreateProcDump $proc.id $global:resDir "svchost-WinMgmt"
        $found = $true
        break
      }
    }
  }
  if (-not $found) {
    Write-Log "Cannot find any process having wmisvc.dll loaded, probably the WMI service is not running"
  }
}

Write-Log "Collecing the dumps of WMIPrvSE.exe processes"
$list = get-process -Name "WmiPrvSe" -ErrorAction SilentlyContinue 2>>$global:errfile
if (($list | Measure-Object).count -gt 0) {
  foreach ($proc in $list)
  {
    Write-Log ("Found WMIPrvSE.exe with PID " + $proc.Id)
    CreateProcDump $proc.id $global:resDir
  }
} else {
  Write-Log "No WMIPrvSE.exe processes found"
}

Write-Log "Collecing the dumps of decoupled WMI providers"
$list = Get-Process
if (($list | Measure-Object).count -gt 0) {
  foreach ($proc in $list)
  {
    $prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "wmidcprv.dll"} 
    if (($prov | Measure-Object).count -gt 0) {
      Write-Log ("Found " + $proc.Name + "(" + $proc.id + ")")
      CreateProcDump $proc.id $global:resDir
    }
  }
}

$proc = get-process "WmiApSrv" -ErrorAction SilentlyContinue
if ($proc) {
  Write-Log "Collecting dump of the WmiApSrv.exe process"
  CreateProcDump $proc.id $global:resDir
}

Write-Log "Collecing the dumps of scrcons.exe processes"
$list = get-process -Name "scrcons" -ErrorAction SilentlyContinue 2>>$global:errfile
if (($list | Measure-Object).count -gt 0) {
  foreach ($proc in $list)
  {
    CreateProcDump $proc.id $global:resDir
  }
} else {
  Write-Log "No scrcons.exe processes found"
}

Write-Log "Collecting Autorecover MOFs content"
$mof = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM")).'Autorecover MOFs'
if ($mof.length -eq 0) {
  Write-Log ("The registry key ""HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM\Autorecover MOFs"" is missing or empty")
  exit
}
$mof | Out-File ($global:resDir + "\Autorecover MOFs.txt")

Write-Log "Listing WBEM folder"
Get-ChildItem $env:windir\system32\wbem -Recurse | Out-File $global:resDir\wbem.txt

Write-Log "Exporting WMIPrvSE AppIDs and CLSIDs registration keys"
$cmd = "reg query ""HKEY_CLASSES_ROOT\AppID\{73E709EA-5D93-4B2E-BBB0-99B7938DA9E4}"" >> """ + $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
$cmd = "reg query ""HKEY_CLASSES_ROOT\AppID\{1F87137D-0E7C-44d5-8C73-4EFFB68962F2}"" >> """+ $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
$cmd = "reg query ""HKEY_CLASSES_ROOT\Wow6432Node\AppID\{73E709EA-5D93-4B2E-BBB0-99B7938DA9E4}"" >> """+ $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
$cmd = "reg query ""HKEY_CLASSES_ROOT\Wow6432Node\AppID\{1F87137D-0E7C-44d5-8C73-4EFFB68962F2}"" >> """+ $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
$cmd = "reg query ""HKEY_CLASSES_ROOT\CLSID\{4DE225BF-CF59-4CFC-85F7-68B90F185355}"" >> """+ $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole """+ $global:resDir + "\Ole.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Rpc"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Rpc """+ $global:resDir + "\Rpc.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Invoke-Expression $cmd

if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc") {
  Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
  $cmd = "reg export ""HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"" """ + $global:resDir + "\Rpc-policies.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $global:errfile + """"
  Invoke-Expression $cmd
}

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Wbem"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Wbem """+ $global:resDir + "\wbem.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Invoke-Expression $cmd

# SCCM automatic remediation exclusion, see https://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/configure-client-status#automatic-remediation-exclusion
Export-RegistryKey -KeyPath "HKLM:\Software\Microsoft\CCM\CcmEval" -DestinationFile "CCMEval.txt"

Write-Log "Getting the output of WHOAMI /all"
$cmd = "WHOAMI /all >>""" + $global:resDir + "\WHOAMI.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Listing members of Remote Management Users group"

$name = Get-LocalGroupNameBySid "S-1-5-32-580"
("Group : " + $name) | Out-File -Append -FilePath ($global:resDir + "\Groups.txt")
$members = Get-LocalGroupMembers $name
if ($members) {
  $members | Out-File -Append -FilePath ($global:resDir + "\Groups.txt")
} else {
  "<empty>" | Out-File -Append -FilePath ($global:resDir + "\Groups.txt")  
}
"" | Out-File -Append -FilePath ($global:resDir + "\Groups.txt")

Write-Log "Exporting Application log"
$cmd = "wevtutil epl Application """+ $global:resDir + "\" + $env:computername + "-Application.evtx"" >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "Application"

Write-Log "Exporting System log"
$cmd = "wevtutil epl System """+ $global:resDir + "\" + $env:computername + "-System.evtx"" >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "System"

Write-Log "Exporting WMI-Activity/Operational log"
$cmd = "wevtutil epl Microsoft-Windows-WMI-Activity/Operational """+ $global:resDir + "\" + $env:computername + "-WMI-Activity.evtx"" >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "WMI-Activity"

if ($PSVersionTable.psversion.ToString() -ge "3.0") {
  $actLog = Get-WinEvent -logname Microsoft-Windows-WMI-Activity/Operational -Oldest -ErrorAction Continue 2>>$global:errfile
  if (($actLog  | Measure-Object).count -gt 0) {
    Write-Log "Exporting WMI-Activity log"
    $actLog | Out-String -width 1000 | Out-File -FilePath ($global:resDir + "\WMI-Activity.txt")
  }
}

Write-Log "Exporting netstat output"
$cmd = "netstat -anob >""" + $global:resDir + "\netstat.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Exporting ipconfig /all output"
$cmd = "ipconfig /all >""" + $global:resDir + "\ipconfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Exporting firewall rules"
$cmd = "netsh advfirewall firewall show rule name=all >""" + $global:resDir + "\FirewallRules.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Enumerating services with SC query"
$cmd = "sc.exe query >>""" + $global:resDir + "\Services-SCQuery.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Exporting service configuration"
$cmd = "sc.exe queryex winmgmt >>""" + $global:resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

$cmd = "sc.exe qc winmgmt >>""" + $global:resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

$cmd = "sc.exe enumdepend winmgmt 3000 >>""" + $global:resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

$cmd = "sc.exe sdshow winmgmt >>""" + $global:resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

FileVersion -Filepath ($env:windir + "\system32\wbem\wbemcore.dll") -Log $true
FileVersion -Filepath ($env:windir + "\system32\wbem\repdrvfs.dll") -Log $true
FileVersion -Filepath ($env:windir + "\system32\wbem\WmiPrvSE.exe") -Log $true
FileVersion -Filepath ($env:windir + "\system32\wbem\WmiPerfClass.dll") -Log $true
FileVersion -Filepath ($env:windir + "\system32\wbem\WmiApRpl.dll") -Log $true

if (((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber) -ge 26063) {
  $cmd = "winmgmt /dumptasks arb 1 LogFile:""" + $global:resDir + "\Arb.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd)

  $cmd = "winmgmt /dumptasks ess 1 LogFile:""" + $global:resDir + "\Ess.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd)
}

Write-Log "Collecting details about running processes"
if (ListProcsAndSvcs) {
  CollectSystemInfoWMI
  ExecQuery -Namespace "root\cimv2" -Query "select * from Win32_Product" | Sort-Object Name | Format-Table -AutoSize -Property Name, Version, Vendor, InstallDate | Out-String -Width 400 | Out-File -FilePath ($global:resDir + "\products.txt")

  Write-Log "Collecting the list of installed hotfixes"
  Get-HotFix -ErrorAction SilentlyContinue 2>>$global:errfile | Sort-Object -Property InstalledOn -ErrorAction Ignore | Out-File $global:resDir\hotfixes.txt

  Write-Log "Collecing GPResult output"
  $cmd = "gpresult /h """ + $global:resDir + "\gpresult.html""" + $RdrErr
  write-log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

  $cmd = "gpresult /r >""" + $global:resDir + "\gpresult.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

  Write-Log "COM Security"
  $Reg = [WMIClass]"\\.\root\default:StdRegProv"
  $DCOMMachineLaunchRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineLaunchRestriction").uValue
  $DCOMMachineAccessRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineAccessRestriction").uValue
  $DCOMDefaultLaunchPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultLaunchPermission").uValue
  $DCOMDefaultAccessPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultAccessPermission").uValue

  # Convert the current permissions to SDDL
  $converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
  "Default Access Permission = " + ($converter.BinarySDToSDDL($DCOMDefaultAccessPermission)).SDDL | Out-File -FilePath ($global:resDir + "\COMSecurity.txt") -Append
  "Default Launch Permission = " + ($converter.BinarySDToSDDL($DCOMDefaultLaunchPermission)).SDDL | Out-File -FilePath ($global:resDir + "\COMSecurity.txt") -Append
  "Machine Access Restriction = " + ($converter.BinarySDToSDDL($DCOMMachineAccessRestriction)).SDDL | Out-File -FilePath ($global:resDir + "\COMSecurity.txt") -Append
  "Machine Launch Restriction = " + ($converter.BinarySDToSDDL($DCOMMachineLaunchRestriction)).SDDL | Out-File -FilePath ($global:resDir + "\COMSecurity.txt") -Append

  Write-Log "Collecting details of provider hosts"
  New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR -ErrorAction SilentlyContinue | Out-Null

  "Coupled providers (WMIPrvSE.exe processes)" | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
  "" | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append

  $totMem = 0
  $prov = ExecQuery -NameSpace "root\cimv2" -Query "select HostProcessIdentifier, Provider, Namespace, User from MSFT_Providers"
  if ($prov) {
    $proc = ExecQuery -NameSpace "root\cimv2" -Query "select ProcessId, HandleCount, ThreadCount, PrivatePageCount, CreationDate, KernelModeTime, UserModeTime from Win32_Process where name = 'wmiprvse.exe'"
    foreach ($prv in $proc) {
      $provhost = $prov | Where-Object {$_.HostProcessIdentifier -eq $prv.ProcessId}

      if (($provhost | Measure-Object).count -gt 0) {
        if ($PSVersionTable.psversion.ToString() -ge "3.0") {
          $ut = New-TimeSpan -Start $prv.CreationDate
        } else {
          $ut = New-TimeSpan -Start $prv.ConvertToDateTime($prv.CreationDate)
        }

        $uptime = ($ut.Days.ToString() + "d " + $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00"))

        $ks = $prv.KernelModeTime / 10000000
        $kt = [timespan]::fromseconds($ks)
        $kh = $kt.Hours.ToString("00") + ":" + $kt.Minutes.ToString("00") + ":" + $kt.Seconds.ToString("00")

        $us = $prv.UserModeTime / 10000000
        $ut = [timespan]::fromseconds($us)
        $uh = $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00")

        "PID" + " " + $prv.ProcessId + " (" + [String]::Format("{0:x}", $prv.ProcessId) + ") Handles:" + $prv.HandleCount +" Threads:" + $prv.ThreadCount + " Private KB:" + ($prv.PrivatePageCount/1kb) + " KernelTime:" + $kh + " UserTime:" + $uh + " Uptime:" + $uptime + " " + (Get-ProcBitness($prv.ProcessId)) | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
        $totMem = $totMem + $prv.PrivatePageCount
      } else {
        Write-Log ("No provider found for the WMIPrvSE process with PID " +  $prv.ProcessId)
      }

      foreach ($provname in $provhost) {
        $provdet = ExecQuery -NameSpace $provname.Namespace -Query ("select * from __Win32Provider where Name = """ + $provname.Provider + """")
        $hm = $provdet.hostingmodel
        $clsid = $provdet.CLSID
        $dll = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKCR:\CLSID\" + $clsid + "\InprocServer32")).'(default)' 2>>$global:errfile
        $dll = $dll.Replace("""","")
        $file = Get-Item ($dll)
        $dtDLL = $file.CreationTime
        $verDLL = $file.VersionInfo.FileVersion

        $provname.Namespace + " " + $provname.Provider + " " + $dll + " " + $hm + " " + $provname.user + " " + $dtDLL + " " + $verDLL 2>>$global:errfile | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
      }
      " " | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
    }
  }
  "Total memory used by coupled providers: " + ($totMem/1kb) + " KB" | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
  " " | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append

  # Details of decoupled providers
  $list = Get-Process
  foreach ($proc in $list) {
    $prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "wmidcprv.dll"} 
    if (($prov | Measure-Object).count -gt 0) {
      if (-not $hdr) {
        "Decoupled providers" | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
        " " | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
        $hdr = $true
      }

      $prc = ExecQuery -Namespace "root\cimv2" -Query ("select ProcessId, CreationDate, HandleCount, ThreadCount, PrivatePageCount, ExecutablePath, KernelModeTime, UserModeTime from Win32_Process where ProcessId = " +  $proc.id)
      if ($PSVersionTable.psversion.ToString() -ge "3.0") {
        $ut= New-TimeSpan -Start $prc.CreationDate
      } else {
        $ut= New-TimeSpan -Start $prc.ConvertToDateTime($prc.CreationDate)
      }

      $uptime = ($ut.Days.ToString() + "d " + $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00"))

      $ks = $prc.KernelModeTime / 10000000
      $kt = [timespan]::fromseconds($ks)
      $kh = $kt.Hours.ToString("00") + ":" + $kt.Minutes.ToString("00") + ":" + $kt.Seconds.ToString("00")

      $us = $prc.UserModeTime / 10000000
      $ut = [timespan]::fromseconds($us)
      $uh = $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00")

      $svc = ExecQuery -Namespace "root\cimv2" -Query ("select Name from Win32_Service where ProcessId = " +  $prc.ProcessId)
      $svclist = ""
      if ($svc) {
        foreach ($item in $svc) {
          $svclist = $svclist + $item.name + " "
        }
        $svc = " Service: " + $svclist
      } else {
        $svc = ""
      }

      ($prc.ExecutablePath + $svc) | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
      "PID " + $prc.ProcessId  + " (" + [String]::Format("{0:x}", $prc.ProcessId) + ")  Handles: " + $prc.HandleCount + " Threads: " + $prc.ThreadCount + " Private KB: " + ($prc.PrivatePageCount/1kb) + " KernelTime:" + $kh + " UserTime:" + $uh + " Uptime:" + $uptime + " " + (Get-ProcBitness($prv.ProcessId)) | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append

      $Keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Wbem\Transports\Decoupled\Client
      $Items = $Keys | Foreach-Object {Get-ItemProperty $_.PsPath }
      ForEach ($key in $Items) {
        if ($key.ProcessIdentifier -eq $prc.ProcessId) {
          ($key.Scope + " " + $key.Provider) | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
        }
      }
      " " | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
    }
  }

  Write-Log "Collecting quota details"
  $quota = ExecQuery -Namespace "Root" -Query "select * from __ProviderHostQuotaConfiguration"
  if ($quota) {
    ("ThreadsPerHost : " + $quota.ThreadsPerHost + "`r`n") + `
    ("HandlesPerHost : " + $quota.HandlesPerHost + "`r`n") + `
    ("ProcessLimitAllHosts : " + $quota.ProcessLimitAllHosts + "`r`n") + `
    ("MemoryPerHost : " + $quota.MemoryPerHost + "`r`n") + `
    ("MemoryAllHosts : " + $quota.MemoryAllHosts + "`r`n") | Out-File -FilePath ($global:resDir + "\ProviderHostQuotaConfiguration.txt")
  }

  ExecQuery -Namespace "root\subscription" -Query "select * from ActiveScriptEventConsumer" | Export-Clixml -Path ($subDir + "\ActiveScriptEventConsumer.xml")
  ExecQuery -Namespace "root\subscription" -Query "select * from __eventfilter" | Export-Clixml -Path ($subDir + "\__eventfilter.xml")
  ExecQuery -Namespace "root\subscription" -Query "select * from __IntervalTimerInstruction" | Export-Clixml -Path ($subDir + "\__IntervalTimerInstruction.xml")
  ExecQuery -Namespace "root\subscription" -Query "select * from __AbsoluteTimerInstruction" | Export-Clixml -Path ($subDir + "\__AbsoluteTimerInstruction.xml")
  ExecQuery -Namespace "root\subscription" -Query "select * from __FilterToConsumerBinding" | Export-Clixml -Path ($subDir + "\__FilterToConsumerBinding.xml")

  Write-Log "Exporting driverquery /v output"
  $cmd = "driverquery /v >""" + $global:resDir + "\drivers.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append
} else {
  Write-Log "WMI is not working"
  $proc = Get-Process | Where-Object {$_.Name -ne "Idle"}
  $proc | Format-Table -AutoSize -property id, name, @{N="WorkingSet";E={"{0:N0}" -f ($_.workingset/1kb)};a="right"},
  @{N="VM Size";E={"{0:N0}" -f ($_.VirtualMemorySize/1kb)};a="right"},
  @{N="Proc time";E={($_.TotalProcessorTime.ToString().substring(0,8))}}, @{N="Threads";E={$_.threads.count}},
  @{N="Handles";E={($_.HandleCount)}}, StartTime, Path | 
  Out-String -Width 300 | Out-File -FilePath ($global:resDir + "\processes.txt")
  CollectSystemInfoNoWMI
}

Write-LogMessage ($DiagVersion)

####################################################################################
#################################### Diag start ####################################
####################################################################################

# Check OS version & get IPs
$OSVer = [environment]::OSVersion.Version.Major + [environment]::OSVersion.Version.Minor * 0.1
if ($OSVer -gt 6.1) {

    $versionRegKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    Write-LogMessage "Host: $($env:COMPUTERNAME)"
    Write-LogMessage "Running on: $($versionRegKey.ProductName)"
    Write-LogMessage "Current build number: $($versionRegKey.CurrentBuildNumber).$($versionRegKey.UBR)"
    Write-LogMessage "Build details: $($versionRegKey.BuildLabEx)"

    # TODO - try to determine when the last CU was installed...not the best option...
    # tried getting the last write time of the build number in the registry, but that's not possible... 
    # can only get a LastWriteTime for a regkey, not for a regvalue
    # https://devblogs.microsoft.com/scripting/use-powershell-to-access-registry-last-modified-time-stamp/
    $xmlQuery = @'
    <QueryList>
        <Query Id="0" Path="Setup">
            <Select Path="Setup">*[System[(EventID=2)]][UserData[CbsPackageChangeState[(Client='UpdateAgentLCU' or Client='WindowsUpdateAgent') and (ErrorCode='0x0')]]]</Select>
        </Query>
    </QueryList>
'@
    $lastSuccessfulCU = Get-WinEvent -MaxEvents 1 -FilterXml $xmlQuery  -ErrorAction SilentlyContinue
    if ($lastSuccessfulCU) {
        if ($lastSuccessfulCU.TimeCreated -le ((Get-Date).AddDays(-90))) {
            Write-LogMessage -Type Warning "This device looks like it may not have had cumulative updates installed recently. Check current build number ($($versionRegKey.UBR)) vs the build number in the latest KBs for this OS."
        }
        Write-LogMessage "The most recent successfully installed cumulative update was $($lastSuccessfulCU.Properties[0].Value), $(((Get-Date) - $lastSuccessfulCU.TimeCreated).Days) days ago @ $($lastSuccessfulCU.TimeCreated)."
    }
    else {
        Write-LogMessage -Type Warning "Could not detect any successful cumulative update installation events. Check current build number ($($versionRegKey.UBR)) vs the build number in the latest KBs for this OS."
    }

    $psver = $PSVersionTable.PSVersion.Major.ToString() + $PSVersionTable.PSVersion.Minor.ToString()
    if ($psver -lt "51") {
        Write-LogMessage -Type Warning "Windows Management Framework version $($PSVersionTable.PSVersion.ToString()) is no longer supported"
    }
    else { 
        Write-LogMessage "Windows Management Framework version is $($PSVersionTable.PSVersion.ToString())"
    }
    Write-LogMessage "Running PowerShell build $($PSVersionTable.BuildVersion.ToString())"

    $iplist = Get-NetIPAddress
    Write-LogMessage "IP addresses of this machine: $(foreach ($ip in $iplist) {$ip.ToString() +' |'})"
}
else {
    Write-LogMessage -Type Warning "This is a legacy OS, please consider updating to a newer supported version."
}

Write-LogMessage "-------------------------"
Write-LogMessage "Checking domain / workgroup settings..."

# Check if machine is part of a domain or not
$computerSystem = Get-CimInstance -ClassName "Win32_ComputerSystem"
switch ($computerSystem.DomainRole) {
    0 { $role = "Standalone Workstation" }
    1 { $role = "Member Workstation" }
    2 { $role = "Standalone Server" }
    3 { $role = "Member Server" }
    4 { $role = "Backup Domain Controller" }
    5 { $role = "Primary Domain Controller" }
    Default { $role = "Unknown" }
}
if ($computerSystem.PartOfDomain) {
    Write-LogMessage "The machine is part of domain: '$($computerSystem.Domain)', having the role of '$($role)'."

    # TODO - more checks for domain joined machines

}
else {
    Write-LogMessage -Type Warning "The machine is not joined to a domain, it is a '$($role)'."

    # TODO - more checks for non-domain joined (WORKGROUP) machines

}

Write-LogMessage "-------------------------"
Write-LogMessage "Checking services..."

# check WMI, RPCSS, DcomLaunch services
$services = Get-Service EventSystem, COMSysApp, RPCSS, RpcEptMapper, DcomLaunch, Winmgmt
if ($services) {
    foreach ($service in $Services) {
        $msg = "The '$($service.DisplayName)' service is $($service.Status)."
        if ($service.Status -eq 'Running') {
            Write-LogMessage -Type Pass $msg
        }
        else {
            Write-LogMessage -Type Error $msg
        }
        if (($service.Name -eq 'COMSysApp') -and ($service.StartType -ne 'Manual')) {
            Write-LogMessage -Type Warning "The service also does not have its default StartupType. Default: Manual. Current setting: $($service.StartType)."
        }
        elseif (($service.Name -ne 'COMSysApp') -and ($service.StartType -ne 'Automatic')) {
            Write-LogMessage -Type Warning "The service also does not have its default StartupType. Default: Automatic. Current setting: $($service.StartType)."
        }
    }
}
else {
    Write-LogMessage -Type Error "Could not check the status of the services, please look into this!"
}   


Write-LogMessage "-------------------------"
Write-LogMessage "Checking COM+ settings..."

# Check if COM+ is on
$enableComPlus = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\COM3").'Com+Enabled'
if ([string]::IsNullOrEmpty($enableComPlus)) {
    Write-LogMessage -Type Warning "Could not check COM+, please check manually @ HKLM:\SOFTWARE\Microsoft\COM3."
}
else {
    if ($enableComPlus -eq 1) {
        Write-LogMessage -Type Pass "COM+ is enabled."
    }
    elseif ($enableComPlus -eq 0) {
        Write-LogMessage -Type Error "COM+ is NOT enabled."
    }
}

# Check if COM+ remote access is on
$remoteComPlus = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\COM3").RemoteAccessEnabled
if ([string]::IsNullOrEmpty($remoteComPlus)) {
    Write-LogMessage -Type Warning "Could not check COM+ remote access, please check manually @ HKLM:\SOFTWARE\Microsoft\COM3."
}
else {
    if ($remoteComPlus -eq 1) {
        Write-LogMessage -Type Warning "COM+ remote access is enabled. By default it is off."
    }
    elseif ($remoteComPlus -eq 0) {
        Write-LogMessage -Type Pass "COM+ remote access is not enabled. This is ok, by default it is off."
    }
}


Write-LogMessage "-------------------------"
Write-LogMessage "Checking RPC settings..."

# Check if the Restrict Unauthenticated RPC clients policy is on or not
$restrictRpcClients = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -ErrorAction SilentlyContinue).RestrictRemoteClients
if ([string]::IsNullOrEmpty($restrictRpcClients)) {
    Write-LogMessage -Type Pass "RPC restrictions via policy are not in place."
}
else {
    switch ($restrictRpcClients) {
        0 { Write-LogMessage "The RPC restriction policy is set to 'None', so all connections are allowed." }
        1 { Write-LogMessage "The RPC restriction policy is set to 'Authenticated', so only Authenticated RPC Clients are allowed. Exemptions are granted to interfaces that have requested them." }
        2 { Write-LogMessage -Type Warning "The RPC restriction policy is set to 'Authenticated without exceptions', so only Authenticated RPC Clients are allowed, with NO exceptions. This is known to cause on the client some very tricky to investigate 'access denied' errors." }
        Default { Write-LogMessage -Type Error "The RPC restriction policy seems to be present, but its value seems to be wrong. It should be 0, 1 or 2, but is actually $($restrictRpcClients)." }
    }
}

# Check if RPC Endpoint Mapper Client Authentication is on or not
$authEpResolution = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc" -ErrorAction SilentlyContinue).EnableAuthEpResolution
if (([string]::IsNullOrEmpty($authEpResolution)) -or ($authEpResolution -eq 0)) {
    Write-LogMessage -Type Pass "RPC Endpoint Mapper Client Authentication is not configured or disabled."
}
elseif ($authEpResolution -eq 1) {
    Write-LogMessage -Type Warning "RPC Endpoint Mapper Client Authentication is enabled, which may cause some issues with applications/components that do not know how to handle this."
}

# Check internet settings for RPC to see if there's a restricted port range
$rpcPortsRestriction = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Rpc\Internet" -ErrorAction SilentlyContinue).UseInternetPorts
if (([string]::IsNullOrEmpty($rpcPortsRestriction)) -or ($rpcPortsRestriction -eq "N")) {
    Write-LogMessage -Type Pass "RPC ports are not restricted."
}
elseif ($rpcPortsRestriction -eq "Y") {
    $rpcPorts = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Rpc\Internet" -ErrorAction SilentlyContinue).Ports
    Write-LogMessage -Type Warning "RPC ports are restricted. This may cause issues with RPC/DCOM connections. The usable port range is defined to '$($rpcPorts.ToString())'."
}

# Check actual dynamic port range
$intSettings = Get-NetTCPSetting -SettingName Internet
if ($null -eq $intSettings) {
    Write-LogMessage -Type Warning "The Internet TCP dynamic port range could not be read, please have a close look."
}
elseif ($intSettings.DynamicPortRangeStartPort -eq 49152 -and $intSettings.DynamicPortRangeNumberOfPorts -eq 16384) {
    Write-LogMessage -Type Pass "The Internet TCP dynamic port range is the default."
}
else {
    Write-LogMessage -Type Warning "The Internet TCP dynamic port range is NOT the default, please have a closer look."
}


Write-LogMessage "-------------------------"
Write-LogMessage "Checking DCOM settings..."

# Check if DCOM is enabled 
$ole = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole"
if ($ole.EnableDCOM -eq "Y") {
    Write-LogMessage -Type Pass "DCOM is enabled."
}
else {
    Write-LogMessage -Type Error "DCOM is NOT enabled! Check the settings."
}

# Check default DCOM Launch & Activation / Access permissions
$defaultPermissions = @(
    @{
        name   = 'Everyone'
        short  = 'WD'
        sid    = 'S-1-1-0'
        launch = 'A;;CCDCSW;;;' 
        access = 'A;;CCDCLC;;;'
    }
    @{
        name   = 'Administrators'
        short  = 'BA'
        sid    = 'S-1-5-32-544'
        launch = 'A;;CCDCLCSWRP;;;'
    }
    @{
        name   = 'Distributed COM Users'
        short  = 'CD'
        sid    = 'S-1-5-32-562'
        launch = 'A;;CCDCLCSWRP;;;'
        access = 'A;;CCDCLC;;;'
    }
    @{
        name   = 'Performance Log Users'
        short  = 'LU'
        sid    = 'S-1-5-32-559'
        launch = 'A;;CCDCLCSWRP;;;'
        access = 'A;;CCDCLC;;;'
    }
    @{
        name   = 'All Application Packages'
        short  = 'AC'
        sid    = 'S-1-15-2-1'
        launch = 'A;;CCDCSW;;;'
        access = 'A;;CCDC;;;'
    }
)

# Get current permissions from registry
$launchRestriction = (([wmiclass]"Win32_SecurityDescriptorHelper").BinarySDToSDDL($ole.MachineLaunchRestriction)).SDDL
$accessRestriction = (([wmiclass]"Win32_SecurityDescriptorHelper").BinarySDToSDDL($ole.MachineAccessRestriction)).SDDL

# Compare current vs default permissions
foreach ($permission in $defaultPermissions.GetEnumerator()) {
    if ($permission.launch) {
        if ($launchRestriction.Contains($permission.launch + $permission.short) -or $launchRestriction.Contains($permission.launch + $permission.sid)) {
            Write-LogMessage -Type Pass "The '$($permission.name)' group is present in Launch & Activation with default permissions."
        }
        else {
            Write-LogMessage -Type Error "The '$($permission.name)' group is NOT present in Launch & Activation with default permissions, please verify."
        }
    }

    if ($permission.access) {
        if ($accessRestriction.Contains($permission.access + $permission.short) -or $accessRestriction.Contains($permission.access + $permission.sid)) {
            Write-LogMessage -Type Pass "The '$($permission.name)' group is present in Access with default permissions."
        }
        else {
            Write-LogMessage -Type Error "The '$($permission.name)' group is NOT present in Access with default permissions, please verify."
        }
    }

    $localGroup = Get-LocalGroup -SID $permission.sid -ErrorAction SilentlyContinue
    if ($localGroup -and !($localGroup.Name -eq $permission.name)) {
        Write-LogMessage -Type Warning "The name of the group is not the original English one (current name: '$($localGroup.Name)'). This is usually because the OS is in a different language & it can cause confusion in some situations, so please be aware / keep this in mind."
    }
}

# Check enabled DCOM protocols
$protocols = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Rpc" -ErrorAction SilentlyContinue).'DCOM Protocols'
if ([string]::IsNullOrEmpty($protocols)) {
    Write-LogMessage -Type Warning "No protocols specified for DCOM."
}
else {
    Write-LogMessage "Enabled protocols: $($protocols)"
    if ($protocols.Contains("ncacn_ip_tcp")) {
        Write-LogMessage -Type Pass "The list of enabled protocols contains 'ncacn_ip_tcp', which should be present by default."
    }
    else {
        Write-LogMessage -Type Error "The list of enabled protocols does NOT contain 'ncacn_ip_tcp', which should be present by default."
    }
}

# Check DcomScmRemoteCallFlags
if ([string]::IsNullOrEmpty($ole.DCOMSCMRemoteCallFlags)) {
    Write-LogMessage -Type Pass "DCOMSCMRemoteCallFlags is not configured in the registry and by default it should not be there. That is ok."
}
else {
    Write-LogMessage -Type Warning "DCOMSCMRemoteCallFlags is configured in the registry with value '$($ole.DCOMSCMRemoteCallFlags)', while it should not be there by default. This does not necessarily mean there is a problem, nevertheless, please check the documentation:`nhttps://learn.microsoft.com/en-us/windows/win32/com/dcomscmremotecallflags"
}

# Check LegacyAuthenticationLevel
if ([string]::IsNullOrEmpty($ole.LegacyAuthenticationLevel)) {
    Write-LogMessage -Type Pass "LegacyAuthenticationLevel is not configured in the registry, so the default is used. That is ok."
}
else {
    Write-LogMessage -Type Warning "LegacyAuthenticationLevel is configured in the registry with value '$($ole.LegacyAuthenticationLevel)', while it should not be there by default. This should not be a problem, though, as we are raising the authentication level in the OS anyway, due to the DCOM hardening. Nevertheless, please check the documentation:`nhttps://learn.microsoft.com/en-us/windows/win32/com/legacyauthenticationlevel"
}

# Check LegacyImpersonationLevel
if ([string]::IsNullOrEmpty($ole.LegacyImpersonationLevel) -or ($ole.LegacyImpersonationLevel -eq 2)) {
    Write-LogMessage -Type Pass "LegacyImpersonationLevel is using the default value. That is ok."
}
else {
    Write-LogMessage -Type Warning "LegacyImpersonationLevel is configured in the registry with value '$($ole.LegacyImpersonationLevel)', while it should be '2' by default. Please check the documentation:`nhttps://learn.microsoft.com/en-us/windows/win32/com/legacyimpersonationlevel"
}

# Check DCOM hardening registry keys
$requireIntegrityAuthLevel = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole\AppCompat" -ErrorAction SilentlyContinue).RequireIntegrityActivationAuthenticationLevel
if ([string]::IsNullOrEmpty($requireIntegrityAuthLevel)) {
    Write-LogMessage -Type Pass "RequireIntegrityActivationAuthenticationLevel is not set in the registry. That is ok."
}
else {
    Write-LogMessage -Type Warning "RequireIntegrityActivationAuthenticationLevel is set in the registry to '$requireIntegrityAuthLevel'. Check info in public KB5004442.`nhttps://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c"
}

$raiseAuthLevel = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole\AppCompat" -ErrorAction SilentlyContinue).RaiseActivationAuthenticationLevel
if ([string]::IsNullOrEmpty($raiseAuthLevel)) {
    Write-LogMessage -Type Pass "RaiseActivationAuthenticationLevel is not set in the registry. That is ok."
}
else {
    Write-LogMessage -Type Warning "RaiseActivationAuthenticationLevel is set in the registry to '$raiseAuthLevel'. Check info in public KB5004442.`nhttps://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c"
}

$disableHardeningLogging = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole\AppCompat" -ErrorAction SilentlyContinue).DisableAuthenticationLevelHardeningLog
if ([string]::IsNullOrEmpty($disableHardeningLogging) -or ($disableHardeningLogging -eq 0)) {
    Write-LogMessage -Type Pass "Hardening related logging is turned on. That is ok, it should be on by default."
}
else {
    Write-LogMessage -Type Error "Hardening related logging is turned off. This is a problem, because you may have failing DCOM calls which you are not aware of. Please turn the logging back on by removing the DisableAuthenticationLevelHardeningLog entry from regkey 'HKLM:\SOFTWARE\Microsoft\Ole\AppCompat'."
}

# Check for any DCOM hardening events (IDs 10036/10037/10038)
$sysEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    ID      = 10036, 10037, 10038
} -ErrorAction SilentlyContinue
if (!$sysEvents) {
    Write-LogMessage -Type Pass "Did not detect any DCOM hardening related events (10036, 10037, 10038) in the System log."
}
else {
    if ($sysEvents.Id.Contains(10036)) {
        Write-LogMessage -Type Warning "Events with ID 10036 detected in the System event log. This device seems to be acting as a DCOM server & is rejecting some incoming connections, please check."
        
        # Print the most recent 5 of them
        Write-LogMessage "Here are the most recent ones:"
        foreach ($event in ($sysEvents | Where-Object { $_.Id -eq 10036 } | Select-Object -First 5)) {
            Write-LogMessage "$($event.TimeCreated) - $($event.Message)"
        }
    }
    if ($sysEvents.Id.Contains(10037)) {
        Write-LogMessage -Type Warning "Events with ID 10037 detected in the System event log. This device seems to be acting as a DCOM client with explicitly set auth level & failing, please check."
          
        # Print the most recent 5 of them
        Write-LogMessage "Here are the most recent ones:"
        foreach ($event in ($sysEvents | Where-Object { $_.Id -eq 10037 } | Select-Object -First 5)) {
            Write-LogMessage "$($event.TimeCreated) - $($event.Message)"
        }
    }
    if ($sysEvents.Id.Contains(10038)) {
        Write-LogMessage -Type Warning "Events with ID 10038 detected in the System event log. This device seems to be acting as a DCOM client with default auth level & failing, please check."
    
        # Print the most recent 5 of them
        Write-LogMessage "Here are the most recent ones:"
        foreach ($event in ($sysEvents | Where-Object { $_.Id -eq 10038 } | Select-Object -First 5)) {
            Write-LogMessage "$($event.TimeCreated) - $($event.Message)"
        }
    }
}


Write-LogMessage "-------------------------"
Write-LogMessage "Checking WMI settings..."

# Check WMI object permissions
New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR -ErrorAction SilentlyContinue | Out-Null
$comWmiObj = Get-ItemProperty -Path "HKCR:\AppID\{8BC3F05E-D86B-11D0-A075-00C04FB68820}" -ErrorAction SilentlyContinue
if (!$comWmiObj) {
    Write-LogMessage -Type Warning "Could not read the permissions for the WMI COM object, please check manually."
}
else {
    $launchWmiPermission = (([wmiclass]"Win32_SecurityDescriptorHelper").BinarySDToSDDL($comWmiObj.LaunchPermission)).SDDL

    $defaultWmiPermissions = @(
        @{
            name   = 'Administrators'
            short  = 'BA'
            sid    = 'S-1-5-32-544'
            launch = 'A;;CCDCLCSWRP;;;'
        }
        @{
            name   = 'Authenticated Users'
            short  = 'AU'
            sid    = 'S-1-5-11'
            launch = 'A;;CCDCSWRP;;;'
        }
    )

    foreach ($permission in $defaultWmiPermissions.GetEnumerator()) {
        if ($launchWmiPermission.Contains($permission.launch + $permission.short) -or $launchWmiPermission.Contains($permission.launch + $permission.sid)) {
            Write-LogMessage -Type Pass "The '$($permission.name)' group is present with default permissions."
        }
        else {
            Write-LogMessage -Type Error "The '$($permission.name)' group is NOT present with default permissions, please verify."
        }

        $localGroup = Get-LocalGroup -SID $permission.sid -ErrorAction SilentlyContinue
        if ($localGroup -and !($localGroup.Name -eq $permission.name)) {
            Write-LogMessage -Type Warning "The name of the group is not the original English one (current name: '$($localGroup.Name)'). This is usually because the OS is in a different language & it can cause confusion in some situations, so please be aware / keep this in mind."
        }
    }
}

# Check event logs for known WMI events in the last 30 days
$cutoffDate = (Get-Date).AddDays(-30)
$wmiProvEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Application'
    ID        = 5612
    StartTime = $cutoffDate
} -ErrorAction SilentlyContinue
if ($wmiProvEvents) {
    Write-LogMessage -Type Warning "Detected $($wmiProvEvents.Count) events with ID 5612 detected in the Application event log in the last 30 days. This means that WmiPrvSE processes are exceeding some quota(s), please check."

    # Print the most recent 5 of them
    Write-LogMessage "Here are the most recent ones:"
    foreach ($event in ($wmiProvEvents | Select-Object -First 5)) {
        Write-LogMessage "$($event.TimeCreated) - $($event.Message)"
    }
}
else {
    Write-LogMessage -Type Pass "Did not detect any WMI Provider Host quota violation events in the Application log."
}

# Check WMI provider host quotas
$defaultQuotas = @(
    @{
        name  = 'ThreadsPerHost'
        value = '256'
    }
    @{
        name  = 'HandlesPerHost'
        value = '4096'
    }
    @{
        name  = 'MemoryPerHost'
        value = '536870912'
    }
    @{
        name  = 'MemoryAllHosts'
        value = '1073741824'
    }
    @{
        name  = 'ProcessLimitAllHosts'
        value = '32'
    }
)
$quotas = Get-CimInstance -Namespace "Root" -ClassName "__ProviderHostQuotaConfiguration"
if ($null -ne $quotas) {
    foreach ($defQuota in $defaultQuotas.GetEnumerator()) {
        if ($defQuota.value -eq $quotas.($defQuota.name)) {
            Write-LogMessage -Type Pass "The WMI provider host quota '$($defQuota.name)' is set to its default value: $($quotas.($defQuota.name))."
        }
        else {
            Write-LogMessage -Type Warning "The WMI provider host quota '$($defQuota.name)' is NOT set to its default value. Default value: '$($defQuota.value)'. Current value: '$($quotas.($defQuota.name))'"
        }
    }
}
else {
    Write-LogMessage -Type Error "Could not read the WMI provider host quotas configuration."
}

# Check for Corrupted.rec file
$corruptionSign = Get-ItemProperty "$env:SystemRoot\System32\wbem\repository\Corrupted.rec" -ErrorAction SilentlyContinue
if ($corruptionSign) {
    Write-LogMessage -Type Warning "Found 'Corrupted.rec' file. This means that the WMI repository could have been corrupted at some point & was restored/reset @ '$($corruptionSign.CreationTimeUtc)'."
    
    # check SCCM client auto remediation setting
    $ccmEval = Get-ItemProperty -Path "HKLM:\Software\Microsoft\CCM\CcmEval" -ErrorAction SilentlyContinue
    if ($ccmEval) {
        if ($ccmEval.NotifyOnly -eq 'TRUE') {
            Write-LogMessage -Type Pass "SCCM client automatic remediation is turned OFF. This should prevent it from automatically resetting the WMI repository."
        }
        else {
            Write-LogMessage -Type Warning "SCCM client automatic remediation is turned ON. This could be an explanation for the repository restore/reset. You can turn this OFF & see if the problem persists, check out this page `nhttps://learn.microsoft.com/en-us/mem/configmgr/core/clients/deploy/configure-client-status#automatic-remediation-exclusion"
        }
    }
}
else {
    Write-LogMessage -Type Pass "Did not find a 'Corrupted.rec' file. This means that the WMI repository is probably healthy & was not restored/reset recently."
}

# Check repository file size
$repoFile = Get-ItemProperty "$env:SystemRoot\System32\wbem\repository\OBJECTS.DATA" -ErrorAction SilentlyContinue
if ($repoFile) {
    $size = $repoFile.Length / 1024 / 1024
    if ($size -lt 500) {
        Write-LogMessage -Type Pass "The WMI repository file is smaller than 500 MB ($size MB). This seems healthy."
    }
    else {
        if ($size -gt 1000) {
            Write-LogMessage -Type Error "The WMI repository file is larger than 1 GB ($size MB). This may cause issues like slow boot/logon."
        }
        else {
            Write-LogMessage -Type Warning "The WMI repository file is larger than 500 MB ($size MB). This may be a sign of repository bloating."
        }

        # check for RSOP logging reg key
        $rsopLogging = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue).RSoPLogging
        if ($rsopLogging -and $rsopLogging -eq 0) {
            Write-LogMessage -Type Pass "RSOP logging seems to be turned off, this is probably not why the repository is bloated."
        }
        else {
            Write-LogMessage -Type Warning "RSOP logging is turned on and this may be why the repository is so big. You can turn off RSOP logging via policy or registry:`nhttps://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.GroupPolicy::RSoPLogging"
        }
    }
}
else {
    Write-LogMessage -Type Warning "Could not get information about the WMI repository file."
}


Write-LogMessage "-------------------------"
Write-LogMessage "Checking networking settings..."

# check firewall remote administration exception policy
$admException = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\RemoteAdminSettings" -ErrorAction SilentlyContinue).Enabled
if (([string]::IsNullOrEmpty($admException)) -or ($admException -eq 0)) {
    Write-LogMessage -Type Pass "The RemoteAdministrationException policy is not configured or disabled. That is ok."
}
elseif ($admException -eq 1) {
    Write-LogMessage -Type Warning "The RemoteAdministrationException policy is turned on."
    $admExceptionList = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\RemoteAdminSettings" -ErrorAction SilentlyContinue).RemoteAddresses
    if ($admExceptionList) {
        Write-LogMessage -Type Warning "These are the addresses that are allowed through: $($admExceptionList)"
    }
}


# check default Firewall rules for WMI 
$fwRules = Show-NetFirewallRule -PolicyStore ActiveStore | Where-Object { ($_.DisplayGroup -like '*WMI*') -and ($_.Direction -eq 'Inbound') }
if ($fwRules) {
    foreach ($rule in $fwRules) {
        if ($rule.Enabled -eq 'True') {
            Write-LogMessage -Type Pass "Firewall rule '$($rule.DisplayName) - Profile: $($rule.Profile)' is enabled."
        }
        else {
            Write-LogMessage -Type Warning "Firewall rule '$($rule.DisplayName) - Profile: $($rule.Profile)' is not enabled."
        }
    }
}
else {
    Write-LogMessage -Type Error "Could not find any relevant Firewall rules, please look into this, as it is not normal!"
}


# Check IP listen filtering
$iplisten = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -ErrorAction SilentlyContinue).ListenOnlyList
if ($iplisten) {
    Write-LogMessage -Type Warning "The IPLISTEN list is not empty, the listed addresses are $(foreach ($ip in $iplisten) {$ip.ToString() +' |'})."
}
else {
    Write-LogMessage -Type Pass "The IPLISTEN list is empty. That's ok: we should listen on all IP addresses by default."
}


# Check winhttp proxy
$binval = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -ErrorAction SilentlyContinue).WinHttPSettings            
$proxylength = $binval[12]            
if ($proxylength -gt 0) {
    $proxy = -join ($binval[(12 + 3 + 1)..(12 + 3 + 1 + $proxylength - 1)] | ForEach-Object { ([char]$_) })            
    Write-LogMessage -Type Warning "A NETSH WINHTTP proxy is configured: $($proxy)"
    $bypasslength = $binval[(12 + 3 + 1 + $proxylength)]            
    if ($bypasslength -gt 0) {            
        $bypasslist = -join ($binval[(12 + 3 + 1 + $proxylength + 3 + 1)..(12 + 3 + 1 + $proxylength + 3 + 1 + $bypasslength)] | ForEach-Object { ([char]$_) })            
        Write-LogMessage -Type Warning "Bypass list: $($bypasslist)"
    }
    else {            
        Write-LogMessage -Type Warning "No bypass list is configured"
    }            
    Write-LogMessage -Type Warning "Remote WMI over DCOM does not work very well through proxies, make sure that the target machine is in the bypass list or remove the proxy"
}
else {
    Write-LogMessage -Type Pass "No NETSH WINHTTP proxy is configured"
}

# Check other kinds of proxy
$userSettings = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
if ($userSettings.AutoConfigUrl) {
    Write-LogMessage -Type Warning "The user has a proxy auto configuration (PAC) file setup: $($userSettings.AutoConfigUrl)"
}
if ($userSettings.ProxyServer) {
    if ($userSettings.ProxyEnable -eq 1) {
        Write-LogMessage -Type Warning "The user has an explicitly configured proxy server which is enabled: $($userSettings.ProxyServer)"
    }
    else {
        Write-LogMessage -Type Info "The user has an explicitly configured proxy server, but it is not enabled: $($userSettings.ProxyServer)"
    }
}

if (!(Test-Path 'HKU:\S-1-5-18')) {
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
}
$systemSettings = Get-ItemProperty "HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
if ($systemSettings.AutoConfigUrl) {
    Write-LogMessage -Type Warning "The system has a proxy auto configuration (PAC) file setup: $($systemSettings.AutoConfigUrl)"
}
if ($systemSettings.ProxyServer) {
    if ($systemSettings.ProxyEnable -eq 1) {
        Write-LogMessage -Type Warning "The system has an explicitly configured proxy server which is enabled: $($systemSettings.ProxyServer)"
    }
    else {
        Write-LogMessage -Type Info "The system has an explicitly configured proxy server, but it is not enabled: $($systemSettings.ProxyServer)"
    }
}

# Check HTTPERR buildup
$dir = $env:windir + "\system32\logfiles\HTTPERR"
if (Test-Path -path $dir) {
    $httperrfiles = Get-ChildItem -path ($dir)
    $msg = "There are $($httperrfiles.Count) files in the folder $dir"
    if ($httperrfiles.Count -gt 100) {
        Write-LogMessage -Type Warning $msg
    }
    else {
        Write-LogMessage $msg
    }
    $size = 0 
    foreach ($file in $httperrfiles) {
        $size += $file.Length
    }
    $size = [System.Math]::Ceiling($size / 1024 / 1024) # Convert to MB
    $msg = "The folder $dir is using $($size.ToString()) MB of disk space."
    if ($size -gt 100) {
        Write-LogMessage -Type Warning $msg
    }
    else {
        Write-LogMessage $msg
    }
}
