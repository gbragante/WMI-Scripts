# WMI-Report (20230420)
# by Gianni Bragante gbrag@microsoft.com

param( [string]$DataPath, [switch]$AcceptEula )

Function Get-WMINamespace($ns) {
  Write-Host $ns
  Get-WMIProviders $ns
  Get-Classes $ns
  Get-WmiNamespaceSecurity $ns
  Get-WmiObject -namespace $ns -class "__Namespace" | sort-object Name  |
  foreach {
    if ((($_.name.Length -le 2) -or ($_.name.Substring(0,3).ToLower() -ne "ms_")) -and (-not($_.name -match "LDAP"))) {
      Get-WMINamespace ($ns + "\" + $_.name)
    }
  }
}

Function Get-WMIProviders ($ns) {
  Get-WmiObject -NameSpace $ns -Class __Win32Provider | sort-object Name  |
  foreach {
    Get-ProvDetails $ns $_.name $_.CLSID $_.HostingModel $_.UnloadTimeout
  }
}

Function Get-Classes ($ns) {
  Get-WmiObject -Namespace $ns -Query "select * from meta_class" | sort-object Name  |
  foreach {
    $dynamic = $_.Qualifiers["dynamic"].Value
    $static = $_.Qualifiers["static"].Value

    if( $abstract -eq $true  -or $dynamic -eq $true ) {
      if ($dynamic -eq $true) { # Dynamic class
        $row = $tbDyn.NewRow()
        $row.NameSpace = $ns
        $row.Name = $_.name
        $row.Provider = $_.qualifiers["Provider"].value
        $tbDyn.Rows.Add($row)
      }
    } else {
      if (-not $_.name.Startswith("__")) {
        if ($static -eq $true) { # Static class = Repository
          $row = $tbStatic.NewRow()
          $row.NameSpace = $ns
          $row.Name = $_.name
          $row.Inst = $_.GetInstances().Count
          $row.Size = GetClassSize -className $_.name -ns $ns 
          $tbStatic.Rows.Add($row)
        } else {
          $row = $tbStatic.NewRow()
          $row.NameSpace = $ns
          $row.Name = $_.name

          $inst = $_.GetInstances().Count # Class with instances, repository as well
          if ($inst  -gt 0) {
            $row.Inst = $Inst
            $row.Size = GetClassSize -className $_.name -ns $ns 
          } else {
            $row.Inst = 0
            $row.Size = 0
          }

          $tbStatic.Rows.Add($row)
        }
      }
    }
  }
}

Function GetClassSize ($ns, $className) {
  $cSize = 0
  $classObj = Get-CimInstance -ClassName $className -Namespace $ns -ErrorAction SilentlyContinue
  if ($classObj) {
    ForEach ($inst in $classObj){
      ForEach($prop in $inst.CimInstanceProperties) {
        switch ($prop.CimType) {
          "SInt8" {$cSize += 1}
          "UInt8" {$cSize += 1}
          "SInt16" {$cSize += 2}
          "UInt16" {$cSize += 2}
          "SInt32" {$cSize += 4}
          "UInt32" {$cSize += 4}
          "SInt64" {$cSize += 8}
          "UInt64" {$cSize += 8}
          "Real32" {$cSize += 4}
          "Real64" {$cSize += 8}
          "Char16" {$cSize += 2}
          "Boolean" {$cSize += 1}
          "Datetime" {$cSize += 8}
          "String" {
            if ($prop.value) {
              $cSize += [Text.Encoding]::Unicode.GetByteCount($prop.value.ToString())
             }
          }
        }
      }
    }
  }
  return $cSize
}

Function Get-ProvDetails($ns, $name, $clsid, $HostingModel, $UnloadTimeout) {
  $row = $tbProv.NewRow()
  $row.NameSpace = $ns
  $row.Name = $name
  $row.HostingModel = $HostingModel
  $row.CLSID= $clsid
  $row.UnloadTimeout = $UnloadTimeout
  $dll = " "

  if ($clsid -ne $null) {
    if ($HostingModel -match "decoupled") {
      $Keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Wbem\Transports\Decoupled\Client
      $Items = $Keys | Foreach-Object {Get-ItemProperty $_.PsPath }
      ForEach ($key in $Items) {
        if ($key.Provider -eq $name) {
          $key.ProcessIdentifier
          $proc = Get-WmiObject -Query ("select ExecutablePath from Win32_Process where ProcessId = " +  $key.ProcessIdentifier)
          $exe = get-item ($proc.ExecutablePath)
          $row.DLL = $proc.ExecutablePath
          $row.dtDLL = $exe.CreationTime
          $row.verDLL = $exe.VersionInfo.FileVersion
          $svc = Get-WmiObject -Query ("select Name from Win32_Service where ProcessId = " +  $key.ProcessIdentifier)
          if ($svc) {
            $row.ThreadingModel = ("Service: " + $svc.Name)
          }
        }
      }
    } elseif ($HostingModel -ne "SelfHost") {
      $name = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKCR:\CLSID\" + $clsid)).'(default)'
      $dll = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKCR:\CLSID\" + $clsid + "\InprocServer32")).'(default)'
      $row.DLL= $dll
      if ($dll) {
        $dll = $dll.Replace("""","")
        $file = Get-Item ($dll)
        $row.dtDLL = $file.CreationTime
        $row.verDLL = $file.VersionInfo.FileVersion
      }
      $row.ThreadingModel = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKCR:\CLSID\" + $clsid + "\InprocServer32")).'ThreadingModel'
    }
  }
  $tbProv.Rows.Add($row)
}

Function Get-WmiNamespaceSecurity {
    # This function comes from https://github.com/KurtDeGreeff/PlayPowershell/blob/master/Get-WmiNamespaceSecurity.ps1
    Param ( [parameter(Mandatory=$true,Position=0)][string] $namespace,
        [string] $computer = ".",
        [System.Management.Automation.PSCredential] $credential = $null)
 
    Process {
        $ErrorActionPreference = "Stop"
 
        Function Get-PermissionFromAccessMask($accessMask) {
            $WBEM_ENABLE            = 1
            $WBEM_METHOD_EXECUTE         = 2
            $WBEM_FULL_WRITE_REP           = 4
            $WBEM_PARTIAL_WRITE_REP     = 8
            $WBEM_WRITE_PROVIDER          = 0x10
            $WBEM_REMOTE_ACCESS            = 0x20
            $READ_CONTROL = 0x20000
            $WRITE_DAC = 0x40000
       
            $WBEM_RIGHTS_FLAGS = $WBEM_ENABLE,$WBEM_METHOD_EXECUTE,$WBEM_FULL_WRITE_REP,`
                $WBEM_PARTIAL_WRITE_REP,$WBEM_WRITE_PROVIDER,$WBEM_REMOTE_ACCESS,`
                $WBEM_RIGHT_SUBSCRIBE,$WBEM_RIGHT_PUBLISH,$READ_CONTROL,$WRITE_DAC
            $WBEM_RIGHTS_STRINGS = "EnableAccount","ExecuteMethod","FullWrite","PartialWrite",`
                "ProviderWrite","RemoteEnable","Subscribe","Publish","ReadSecurity","WriteSecurity"
 
            $permission = @()
            for ($i = 0; $i -lt $WBEM_RIGHTS_FLAGS.Length; $i++) {
                if (($accessMask -band $WBEM_RIGHTS_FLAGS[$i]) -gt 0) {
                    $permission += $WBEM_RIGHTS_STRINGS[$i]
                }
            }
       
            $permission
        }

        $res = "" 
        $INHERITED_ACE_FLAG = 0x10
 
        $invokeparams = @{Namespace=$namespace;Path="__systemsecurity=@";Name="GetSecurityDescriptor";ComputerName=$computer}
 
        if ($credential -eq $null) {
            $credparams = @{}
        } else {
            $credparams = @{Credential=$credential}
        }
 
        $output = Invoke-WmiMethod @invokeparams @credparams -ErrorAction SilentlyContinue
        if ($output.ReturnValue -ne 0) {
            $res = "GetSecurityDescriptor failed:" + $output.ReturnValue + "   "
        }
   
        $acl = $output.Descriptor
        foreach ($ace in $acl.DACL) {
            $user = New-Object System.Management.Automation.PSObject
            $user | Add-Member -MemberType NoteProperty -Name "Name" -Value "$($ace.Trustee.Domain)\$($ace.Trustee.Name)"
            $user | Add-Member -MemberType NoteProperty -Name "Permission" -Value (Get-PermissionFromAccessMask($ace.AccessMask))
            $user | Add-Member -MemberType NoteProperty -Name "Inherited" -Value (($ace.AceFlags -band $INHERITED_ACE_FLAG) -gt 0)
            $res = $res + ($user.Name + " (" + ($user.permission -join " ") + ")") + " / "
        }
        $row = $tbSec.NewRow()
        $row.NameSpace = $namespace
        $row.Security = $res.Substring(0, $res.Length -3)
        $tbSec.Rows.Add($row)
    }
}

[void][System.Reflection.Assembly]::Load('System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
[void][System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')

function ShowEULAPopup($mode)
{
    $EULA = New-Object -TypeName System.Windows.Forms.Form
    $richTextBox1 = New-Object System.Windows.Forms.RichTextBox
    $btnAcknowledge = New-Object System.Windows.Forms.Button
    $btnCancel = New-Object System.Windows.Forms.Button

    $EULA.SuspendLayout()
    $EULA.Name = "EULA"
    $EULA.Text = "Microsoft Diagnostic Tools End User License Agreement"

    $richTextBox1.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $richTextBox1.Location = New-Object System.Drawing.Point(12,12)
    $richTextBox1.Name = "richTextBox1"
    $richTextBox1.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
    $richTextBox1.Size = New-Object System.Drawing.Size(776, 397)
    $richTextBox1.TabIndex = 0
    $richTextBox1.ReadOnly=$True
    $richTextBox1.Add_LinkClicked({Start-Process -FilePath $_.LinkText})
    $richTextBox1.Rtf = @"
{\rtf1\ansi\ansicpg1252\deff0\nouicompat{\fonttbl{\f0\fswiss\fprq2\fcharset0 Segoe UI;}{\f1\fnil\fcharset0 Calibri;}{\f2\fnil\fcharset0 Microsoft Sans Serif;}}
{\colortbl ;\red0\green0\blue255;}
{\*\generator Riched20 10.0.19041}{\*\mmathPr\mdispDef1\mwrapIndent1440 }\viewkind4\uc1 
\pard\widctlpar\f0\fs19\lang1033 MICROSOFT SOFTWARE LICENSE TERMS\par
Microsoft Diagnostic Scripts and Utilities\par
\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15 
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}These license terms are an agreement between you and Microsoft Corporation (or one of its affiliates). IF YOU COMPLY WITH THESE LICENSE TERMS, YOU HAVE THE RIGHTS BELOW. BY USING THE SOFTWARE, YOU ACCEPT THESE TERMS.\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15 
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}\par
\pard 
{\pntext\f0 1.\tab}{\*\pn\pnlvlbody\pnf0\pnindent0\pnstart1\pndec{\pntxta.}}
\fi-360\li360 INSTALLATION AND USE RIGHTS. Subject to the terms and restrictions set forth in this license, Microsoft Corporation (\ldblquote Microsoft\rdblquote ) grants you (\ldblquote Customer\rdblquote  or \ldblquote you\rdblquote ) a non-exclusive, non-assignable, fully paid-up license to use and reproduce the script or utility provided under this license (the "Software"), solely for Customer\rquote s internal business purposes, to help Microsoft troubleshoot issues with one or more Microsoft products, provided that such license to the Software does not include any rights to other Microsoft technologies (such as products or services). \ldblquote Use\rdblquote  means to copy, install, execute, access, display, run or otherwise interact with the Software. \par
\pard\widctlpar\par
\pard\widctlpar\li360 You may not sublicense the Software or any use of it through distribution, network access, or otherwise. Microsoft reserves all other rights not expressly granted herein, whether by implication, estoppel or otherwise. You may not reverse engineer, decompile or disassemble the Software, or otherwise attempt to derive the source code for the Software, except and to the extent required by third party licensing terms governing use of certain open source components that may be included in the Software, or remove, minimize, block, or modify any notices of Microsoft or its suppliers in the Software. Neither you nor your representatives may use the Software provided hereunder: (i) in a way prohibited by law, regulation, governmental order or decree; (ii) to violate the rights of others; (iii) to try to gain unauthorized access to or disrupt any service, device, data, account or network; (iv) to distribute spam or malware; (v) in a way that could harm Microsoft\rquote s IT systems or impair anyone else\rquote s use of them; (vi) in any application or situation where use of the Software could lead to the death or serious bodily injury of any person, or to physical or environmental damage; or (vii) to assist, encourage or enable anyone to do any of the above.\par
\par
\pard\widctlpar\fi-360\li360 2.\tab DATA. Customer owns all rights to data that it may elect to share with Microsoft through using the Software. You can learn more about data collection and use in the help documentation and the privacy statement at {{\field{\*\fldinst{HYPERLINK https://aka.ms/privacy }}{\fldrslt{https://aka.ms/privacy\ul0\cf0}}}}\f0\fs19 . Your use of the Software operates as your consent to these practices.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 3.\tab FEEDBACK. If you give feedback about the Software to Microsoft, you grant to Microsoft, without charge, the right to use, share and commercialize your feedback in any way and for any purpose.\~ You will not provide any feedback that is subject to a license that would require Microsoft to license its software or documentation to third parties due to Microsoft including your feedback in such software or documentation. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 4.\tab EXPORT RESTRICTIONS. Customer must comply with all domestic and international export laws and regulations that apply to the Software, which include restrictions on destinations, end users, and end use. For further information on export restrictions, visit {{\field{\*\fldinst{HYPERLINK https://aka.ms/exporting }}{\fldrslt{https://aka.ms/exporting\ul0\cf0}}}}\f0\fs19 .\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 5.\tab REPRESENTATIONS AND WARRANTIES. Customer will comply with all applicable laws under this agreement, including in the delivery and use of all data. Customer or a designee agreeing to these terms on behalf of an entity represents and warrants that it (i) has the full power and authority to enter into and perform its obligations under this agreement, (ii) has full power and authority to bind its affiliates or organization to the terms of this agreement, and (iii) will secure the permission of the other party prior to providing any source code in a manner that would subject the other party\rquote s intellectual property to any other license terms or require the other party to distribute source code to any of its technologies.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 6.\tab DISCLAIMER OF WARRANTY. THE SOFTWARE IS PROVIDED \ldblquote AS IS,\rdblquote  WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL MICROSOFT OR ITS LICENSORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\par
\pard\widctlpar\qj\par
\pard\widctlpar\fi-360\li360\qj 7.\tab LIMITATION ON AND EXCLUSION OF DAMAGES. IF YOU HAVE ANY BASIS FOR RECOVERING DAMAGES DESPITE THE PRECEDING DISCLAIMER OF WARRANTY, YOU CAN RECOVER FROM MICROSOFT AND ITS SUPPLIERS ONLY DIRECT DAMAGES UP TO U.S. $5.00. YOU CANNOT RECOVER ANY OTHER DAMAGES, INCLUDING CONSEQUENTIAL, LOST PROFITS, SPECIAL, INDIRECT, OR INCIDENTAL DAMAGES. This limitation applies to (i) anything related to the Software, services, content (including code) on third party Internet sites, or third party applications; and (ii) claims for breach of contract, warranty, guarantee, or condition; strict liability, negligence, or other tort; or any other claim; in each case to the extent permitted by applicable law. It also applies even if Microsoft knew or should have known about the possibility of the damages. The above limitation or exclusion may not apply to you because your state, province, or country may not allow the exclusion or limitation of incidental, consequential, or other damages.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 8.\tab BINDING ARBITRATION AND CLASS ACTION WAIVER. This section applies if you live in (or, if a business, your principal place of business is in) the United States.  If you and Microsoft have a dispute, you and Microsoft agree to try for 60 days to resolve it informally. If you and Microsoft can\rquote t, you and Microsoft agree to binding individual arbitration before the American Arbitration Association under the Federal Arbitration Act (\ldblquote FAA\rdblquote ), and not to sue in court in front of a judge or jury. Instead, a neutral arbitrator will decide. Class action lawsuits, class-wide arbitrations, private attorney-general actions, and any other proceeding where someone acts in a representative capacity are not allowed; nor is combining individual proceedings without the consent of all parties. The complete Arbitration Agreement contains more terms and is at {{\field{\*\fldinst{HYPERLINK https://aka.ms/arb-agreement-4 }}{\fldrslt{https://aka.ms/arb-agreement-4\ul0\cf0}}}}\f0\fs19 . You and Microsoft agree to these terms. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 9.\tab LAW AND VENUE. If U.S. federal jurisdiction exists, you and Microsoft consent to exclusive jurisdiction and venue in the federal court in King County, Washington for all disputes heard in court (excluding arbitration). If not, you and Microsoft consent to exclusive jurisdiction and venue in the Superior Court of King County, Washington for all disputes heard in court (excluding arbitration).\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 10.\tab ENTIRE AGREEMENT. This agreement, and any other terms Microsoft may provide for supplements, updates, or third-party applications, is the entire agreement for the software.\par
\pard\sa200\sl276\slmult1\f1\fs22\lang9\par
\pard\f2\fs17\lang2057\par
}
"@
    $richTextBox1.BackColor = [System.Drawing.Color]::White
    $btnAcknowledge.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $btnAcknowledge.Location = New-Object System.Drawing.Point(544, 415)
    $btnAcknowledge.Name = "btnAcknowledge";
    $btnAcknowledge.Size = New-Object System.Drawing.Size(119, 23)
    $btnAcknowledge.TabIndex = 1
    $btnAcknowledge.Text = "Accept"
    $btnAcknowledge.UseVisualStyleBackColor = $True
    $btnAcknowledge.Add_Click({$EULA.DialogResult=[System.Windows.Forms.DialogResult]::Yes})

    $btnCancel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $btnCancel.Location = New-Object System.Drawing.Point(669, 415)
    $btnCancel.Name = "btnCancel"
    $btnCancel.Size = New-Object System.Drawing.Size(119, 23)
    $btnCancel.TabIndex = 2
    if($mode -ne 0)
    {
	    $btnCancel.Text = "Close"
    }
    else
    {
	    $btnCancel.Text = "Decline"
    }
    $btnCancel.UseVisualStyleBackColor = $True
    $btnCancel.Add_Click({$EULA.DialogResult=[System.Windows.Forms.DialogResult]::No})

    $EULA.AutoScaleDimensions = New-Object System.Drawing.SizeF(6.0, 13.0)
    $EULA.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
    $EULA.ClientSize = New-Object System.Drawing.Size(800, 450)
    $EULA.Controls.Add($btnCancel)
    $EULA.Controls.Add($richTextBox1)
    if($mode -ne 0)
    {
	    $EULA.AcceptButton=$btnCancel
    }
    else
    {
        $EULA.Controls.Add($btnAcknowledge)
	    $EULA.AcceptButton=$btnAcknowledge
        $EULA.CancelButton=$btnCancel
    }
    $EULA.ResumeLayout($false)
    $EULA.Size = New-Object System.Drawing.Size(800, 650)

    Return ($EULA.ShowDialog())
}

function ShowEULAIfNeeded($toolName, $mode)
{
	$eulaRegPath = "HKCU:Software\Microsoft\CESDiagnosticTools"
	$eulaAccepted = "No"
	$eulaValue = $toolName + " EULA Accepted"
	if(Test-Path $eulaRegPath)
	{
		$eulaRegKey = Get-Item $eulaRegPath
		$eulaAccepted = $eulaRegKey.GetValue($eulaValue, "No")
	}
	else
	{
		$eulaRegKey = New-Item $eulaRegPath
	}
	if($mode -eq 2) # silent accept
	{
		$eulaAccepted = "Yes"
       		$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
	}
	else
	{
		if($eulaAccepted -eq "No")
		{
			$eulaAccepted = ShowEULAPopup($mode)
			if($eulaAccepted -eq [System.Windows.Forms.DialogResult]::Yes)
			{
	        		$eulaAccepted = "Yes"
	        		$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
			}
		}
	}
	return $eulaAccepted
}

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

$global:Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path

$resName = "WMI-Report-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)
$global:resDir = $global:Root + "\" + $resName

if ($AcceptEula) {
  Write-Host "AcceptEula switch specified, silently continuing"
  $eulaAccepted = ShowEULAIfNeeded "WMI-Report" 2
} else {
  $eulaAccepted = ShowEULAIfNeeded "WMI-Report" 0
  if($eulaAccepted -ne "Yes")
  {
    Write-Host "EULA declined, exiting"
    exit
  }
}
Write-Host "EULA accepted, continuing"

if ($DataPath) {
  if (-not (Test-Path $DataPath)) {
    Write-Host "The folder $DataPath does not exist"
    exit
  }
  $global:resDir = $DataPath
} else {
  $global:resDir = $global:Root + "\" + $resName
}

New-Item -itemtype directory -path $global:resDir | Out-Null

New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR | Out-Null

$tbProv = New-Object system.Data.DataTable “WmiProv”
$col = New-Object system.Data.DataColumn NameSpace,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn Name,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn HostingModel,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn ThreadingModel,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn DLL,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn dtDLL,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn verDLL,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn UnloadTimeout,([string])
$tbProv.Columns.Add($col)
$col = New-Object system.Data.DataColumn CLSID,([string])
$tbProv.Columns.Add($col)

$tbDyn = New-Object system.Data.DataTable “Classes”
$col = New-Object system.Data.DataColumn NameSpace,([string])
$tbDyn.Columns.Add($col)
$col = New-Object system.Data.DataColumn Name,([string])
$tbDyn.Columns.Add($col)
$col = New-Object system.Data.DataColumn Provider,([string])
$tbDyn.Columns.Add($col)

$tbStatic = New-Object system.Data.DataTable “Repository”
$col = New-Object system.Data.DataColumn NameSpace,([string])
$tbStatic.Columns.Add($col)
$col = New-Object system.Data.DataColumn Name,([string])
$tbStatic.Columns.Add($col)
$col = New-Object system.Data.DataColumn Inst,([Int32])
$tbStatic.Columns.Add($col)
$col = New-Object system.Data.DataColumn Size,([Int64])
$tbStatic.Columns.Add($col)

$tbSec = New-Object system.Data.DataTable “Security”
$col = New-Object system.Data.DataColumn NameSpace,([string])
$tbSec.Columns.Add($col)
$col = New-Object system.Data.DataColumn Security,([string])
$tbSec.Columns.Add($col)


Get-WMINamespace "Root"

Write-Host "Writing Providers.csv"
$tbProv | Export-Csv $global:resDir"\Providers.csv" -noType
Write-Host "Writing Classes.csv"
$tbDyn | Export-Csv $global:resDir"\Dynamic.csv" -noType
Write-Host "Writing Repository.csv"
$tbStatic | Export-Csv $global:resDir"\Static.csv" -noType
Write-Host "Writing Security.csv"
$tbSec | Export-Csv $global:resDir"\Security.csv" -noType
