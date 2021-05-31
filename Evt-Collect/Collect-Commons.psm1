Function Write-Log {
  param( [string] $msg )

  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg
  $msg | Out-File -FilePath $global:outfile -Append
}

Function ExecQuery {
  param(
    [string] $NameSpace,
    [string] $Query
  )
  Write-Log ("Executing query " + $Query)
  if ($PSVersionTable.psversion.ToString() -ge "3.0") {
    $ret = Get-CimInstance -Namespace $NameSpace -Query $Query -ErrorAction Continue 2>>$errfile
  } else {
    $ret = Get-WmiObject -Namespace $NameSpace -Query $Query -ErrorAction Continue 2>>$errfile
  }
  Write-Log (($ret | measure).count.ToString() + " results")
  return $ret
}

Function ArchiveLog {
  param( [string] $LogName )
  $cmd = "wevtutil al """+ $global:resDir + "\" + $env:computername + "-" + $LogName + ".evtx"" /l:en-us >>""" + $global:outfile + """ 2>>""" + $errfile + """"
  Write-Log $cmd
  Invoke-Expression $cmd
}

Function Win10Ver {
  param(
    [string] $Build
  )

  if ($build -eq 14393) {
    return " (RS1 / 1607)"
  } elseif ($build -eq 15063) {
    return " (RS2 / 1703)"
  } elseif ($build -eq 16299) {
    return " (RS3 / 1709)"
  } elseif ($build -eq 17134) {
    return " (RS4 / 1803)"
  } elseif ($build -eq 17763) {
    return " (RS5 / 1809)"
  } elseif ($build -eq 18362) {
    return " (19H1 / 1903)"
  } elseif ($build -eq 18363) {
    return " (19H2 / 1909)"    
  } elseif ($build -eq 19041) {
    return " (20H1)"  
  } elseif ($build -eq 19042) {
    return " (20H2)"  
  } elseif ($build -eq 19043) {
    return " (21H1)"  
  }
}

Add-Type -MemberDefinition @"
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint NetApiBufferFree(IntPtr Buffer);
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int NetGetJoinInformation(
  string server,
  out IntPtr NameBuffer,
  out int BufferType);
"@ -Namespace Win32Api -Name NetApi32

Function GetNBDomainName {
  $pNameBuffer = [IntPtr]::Zero
  $joinStatus = 0
  $apiResult = [Win32Api.NetApi32]::NetGetJoinInformation(
    $null,               # lpServer
    [Ref] $pNameBuffer,  # lpNameBuffer
    [Ref] $joinStatus    # BufferType
  )
  if ( $apiResult -eq 0 ) {
    [Runtime.InteropServices.Marshal]::PtrToStringAuto($pNameBuffer)
    [Void] [Win32Api.NetApi32]::NetApiBufferFree($pNameBuffer)
  }
}

$UserDumpCode=@'
using System;
using System.Runtime.InteropServices;

namespace MSDATA
{
    public static class UserDump
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessID);
        [DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        public static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeHandle hFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

        private enum MINIDUMP_TYPE
        {
            MiniDumpNormal = 0x00000000,
            MiniDumpWithDataSegs = 0x00000001,
            MiniDumpWithFullMemory = 0x00000002,
            MiniDumpWithHandleData = 0x00000004,
            MiniDumpFilterMemory = 0x00000008,
            MiniDumpScanMemory = 0x00000010,
            MiniDumpWithUnloadedModules = 0x00000020,
            MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
            MiniDumpFilterModulePaths = 0x00000080,
            MiniDumpWithProcessThreadData = 0x00000100,
            MiniDumpWithPrivateReadWriteMemory = 0x00000200,
            MiniDumpWithoutOptionalData = 0x00000400,
            MiniDumpWithFullMemoryInfo = 0x00000800,
            MiniDumpWithThreadInfo = 0x00001000,
            MiniDumpWithCodeSegs = 0x00002000
        };

        public static bool GenerateUserDump(uint ProcessID, string dumpFileName)
        {
            System.IO.FileStream fileStream = System.IO.File.OpenWrite(dumpFileName);

            if (fileStream == null)
            {
                return false;
            }

            // 0x1F0FFF = PROCESS_ALL_ACCESS
            IntPtr ProcessHandle = OpenProcess(0x1F0FFF, false, ProcessID);

            if(ProcessHandle == null)
            {
                return false;
            }

            MINIDUMP_TYPE Flags =
                MINIDUMP_TYPE.MiniDumpWithFullMemory |
                MINIDUMP_TYPE.MiniDumpWithFullMemoryInfo |
                MINIDUMP_TYPE.MiniDumpWithHandleData |
                MINIDUMP_TYPE.MiniDumpWithUnloadedModules |
                MINIDUMP_TYPE.MiniDumpWithThreadInfo;

            bool Result = MiniDumpWriteDump(ProcessHandle,
                                 ProcessID,
                                 fileStream.SafeFileHandle,
                                 (uint)Flags,
                                 IntPtr.Zero,
                                 IntPtr.Zero,
                                 IntPtr.Zero);

            fileStream.Close();
            return Result;
        }
    }
}
'@
add-type -TypeDefinition $UserDumpCode -Language CSharp

Function CreateProcDump {
  param( $ProcID, $DumpFolder, $filename)
  if (-not (Test-Path $DumpFolder)) {
    Write-host ("The folder " + $DumpFolder + " does not exist")
    return $false
  }
  $DumpCreated = $false

  $proc = Get-Process -ID $ProcID
  if (-not $proc) {
    Write-Log "The process with PID $ProcID is not running"
    return $false
  }
  if (-not $Filename) { $filename = $proc.Name }
  $DumpFile = $DumpFolder + "\" + $filename + "-" + $ProcID + "_" + (get-date).ToString("yyyyMMdd_HHmmss") + ".dmp"
  
  if (Test-Path ($global:root + "\procdump.exe")) {
    $cmd = "&""" + $global:root + "\procdump.exe"" -accepteula -ma $ProcID """ + $DumpFile + """ >>""" + $global:outfile + """ 2>>""" + $errfile + """"
    Write-Log $cmd
    Invoke-Expression $cmd

    if (Test-Path $DumpFile) {
      if ((Get-Item $DumpFile).length -gt 1000) {
        $DumpCreated = $true
        Write-Log "Successfully created $DumpFile with ProcDump"
      } else {
        Write-Log "The created dump file is too small, removing it"
        Remove-Item $DumpFile
      }
    } else {
      Write-Log "Cannot find the dump file"
    }
  }

  if (-not $DumpCreated) {
    Write-Log "Cannot create the dump with ProcDump, trying the backup method"
    if ([MSDATA.UserDump]::GenerateUserDump($ProcID, $DumpFile)) {
      Write-Log ("The dump for the Process ID $ProcID was generated as $DumpFile")
    } else {
      Write-Log "Failed to create the dump for the Process ID $ProcID"
    }
  }
}

$FindPIDCode=@'
using System;
using System.ServiceProcess;
using System.Diagnostics;
using System.Threading;
using System.Runtime.InteropServices;

namespace MSDATA {
  public static class FindService {

    public static void Main(){
	  Console.WriteLine("Hello world!");
	}

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct SERVICE_STATUS_PROCESS {
      public int serviceType;
      public int currentState;
      public int controlsAccepted;
      public int win32ExitCode;
      public int serviceSpecificExitCode;
      public int checkPoint;
      public int waitHint;
      public int processID;
      public int serviceFlags;
    }

    [DllImport("advapi32.dll")]
    public static extern bool QueryServiceStatusEx(IntPtr serviceHandle, int infoLevel, IntPtr buffer, int bufferSize, out int bytesNeeded);

    public static int FindServicePid(string SvcName) {
      //Console.WriteLine("Hello world!");
      ServiceController sc = new ServiceController(SvcName);
      if (sc == null) {
        return -1;
      }
                  
      IntPtr zero = IntPtr.Zero;
      int SC_STATUS_PROCESS_INFO = 0;
      int ERROR_INSUFFICIENT_BUFFER = 0;

      Int32 dwBytesNeeded;
      System.IntPtr hs = sc.ServiceHandle.DangerousGetHandle();

      // Call once to figure the size of the output buffer.
      QueryServiceStatusEx(hs, SC_STATUS_PROCESS_INFO, zero, 0, out dwBytesNeeded);
      if (Marshal.GetLastWin32Error() == ERROR_INSUFFICIENT_BUFFER) {
        // Allocate required buffer and call again.
        zero = Marshal.AllocHGlobal((int)dwBytesNeeded);

        if (QueryServiceStatusEx(hs, SC_STATUS_PROCESS_INFO, zero, dwBytesNeeded, out dwBytesNeeded)) {
          SERVICE_STATUS_PROCESS ssp = (SERVICE_STATUS_PROCESS)Marshal.PtrToStructure(zero, typeof(SERVICE_STATUS_PROCESS));
          return (int)ssp.processID;
        }
      }
      return -1;
    }
  }
}
'@
add-type -TypeDefinition $FindPIDCode -Language CSharp -ReferencedAssemblies System.ServiceProcess

Function FindServicePid {
  param( $SvcName)
  try {
    $pidsvc = [MSDATA.FindService]::FindServicePid($SvcName)
    return $pidsvc
  }
  catch {
    return $null
  }
}

Function FileVersion {
  param(
    [string] $FilePath,
    [bool] $Log = $false
  )
  if (Test-Path -Path $FilePath) {
    $fileobj = Get-item $FilePath
    $filever = $fileobj.VersionInfo.FileMajorPart.ToString() + "." + $fileobj.VersionInfo.FileMinorPart.ToString() + "." + $fileobj.VersionInfo.FileBuildPart.ToString() + "." + $fileobj.VersionInfo.FilePrivatepart.ToString()

    if ($log) {
      $LogFile = $global:resDir + "\FilesVersion.csv"
      if (-not (Test-Path -Path $LogFile)) {
        "File,Version,Date,Manufacturer,Description" | Out-File -FilePath ($LogFile)
      }
      ($FilePath + "," + $filever + "," + $fileobj.CreationTime.ToString("yyyyMMdd HH:mm:ss") + "," + $fileobj.VersionInfo.CompanyName + "," + $fileobj.VersionInfo.FileDescription) | Out-File -FilePath ($LogFile) -Append
    }
    return $filever | Out-Null
  } else {
    return ""
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

Export-ModuleMember -Function *
