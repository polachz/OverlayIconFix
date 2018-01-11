<#
	.Synopsis
		 Allows to nanages Overlay Icons order and allow to protect them against third-party modifications

    .Description
		This script handle Overlay Icons registry key and sub-items order. Because Windows supports only 15
		overlay icons, very often we can't see required icons, because are onder 15 items limot, or pushed
		down by another service (DropBox is famous about that). This script allows to lock the Registry key
		against SYSTEM account modifications and can re-order Icon items to order specified by Order file.
		This file can be generqated by this script too and then modified to fit your needs.
		
	.Parameter Action    
        Specifies required action: createOrderFile, dumpOrderFile, showRegistry, reorderRegistry
		lockRegistryKey, restoreRegistryKey, fixAndLock
 
    .Parameter OrderFilePath    
        Specifies path to Order file. This file specifies required order of Overlay Icon Records in the Registry
		If empty, script expects the file "orderFile.txt" in current directory
    
    .Example
        overlayIconFix.ps1 showRegistry
		Show current content of the Overlay Icons registry Key. This piece of information allow to check
		currently available Overlay Icon Items and check their order.
		
    .Example
        overlayIconFix.ps1 createOrderFile -OrderFilePath X:\order.txt
		Creates Order file from current Registry content. You can then modify order of items in the file to 
		fit your needs.

	.Example
        overlayIconFix.ps1 fixAndLock -OrderFilePath X:\order.txt
		This is the base operation of the script. It Locks the registry key with Overlay Icon Records against 
		modifications. This is necessary to block Dropbox or other simmilar services to provide own reordering 
		of the Icon records. Then script re-order Icon records to same order as specified in the Order file.
		In details, it executes lockRegistryKey and reorderRegistry operations in one run.

    .Example
        overlayIconFix.ps1 dumpOrderFile X:\order.txt
		Dumps content of the specified Order file to check if order of items is correct.
	
	.Example
        overlayIconFix.ps1 lockRegistryKey
		Locks the registry key with Overlay Icon Records against modifications from other processes running 
		under SYSTEM account. It block Dropbox or other simmilar services to provide own reordering of
		the Icon records. In details it changes owner of the Key and Sub-Keys to Administrators group, disable 
		Access Right Inheritance on the key and then remove Write rights for the SYSTEM account. 
		
	.Example
        overlayIconFix.ps1 reorderRegistry -OrderFilePath X:\order.txt
		Re-orders Icon records to same order as specified in the Order file. 
		Can be used many times to organize Icons to required order. But without lock it can be change by
		other service easily as for exaple DropBox does. 
		 
	.Example
        overlayIconFix.ps1 restoreRegistryKey
		Remove Lock from the Overlay Icons Registry key and restore it to original state. Returns ownership to 
		the SYSTEM account, enable inheritance again and restore access rights to the key to original values.

    .Notes
        NAME:      overlayIconFix.ps1
        AUTHOR:    Zdenek Polach
		WEBSITE:   https://polach.me

#>

[CmdletBinding(SupportsShouldProcess=$True)]
Param(
	[Parameter(Mandatory=$True,Position=1)][ValidateSet("createOrderFile","dumpOrderFile","showRegistry","reorderRegistry", "lockRegistryKey", "restoreRegistryKey", "fixAndLock")][string]$Action,
	[string]$OrderFilePath =".\orderFile.txt"
)

#path to Overlay Icons Registry Key 
$RegPath="Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers"

#dummy value for internal purposes. It's used to detect Order File unused items
$dummyItem ="&*&Dummy"


#script to allow get rights necessary to change RegKey owner
$definition = @'
 using System;
 using System.Runtime.InteropServices;
  
 public class AdjPriv
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
   ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }
  
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
  {
   bool retVal;
   TokPriv1Luid tp;
   IntPtr hproc = new IntPtr(processHandle);
   IntPtr htok = IntPtr.Zero;
   retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
   tp.Count = 1;
   tp.Luid = 0;
   if(disable)
   {
    tp.Attr = SE_PRIVILEGE_DISABLED;
   }
   else
   {
    tp.Attr = SE_PRIVILEGE_ENABLED;
   }
   retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
   retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
   return retVal;
  }
 }
'@

#define type with C# implementation from the $definition variable
#this action is persistent for powershell instance
#then second script run reports that definition already exist
#it is supressed by this try catch block
try{
 Add-Type -TypeDefinition $definition -ErrorAction SilentlyContinue | Out-Null
}catch{

}

function enable-privilege {
 param(
  ## The privilege to adjust. This set is taken from
  ## http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx
  [ValidateSet(
   "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
   "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
   "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
   "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
   "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
   "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
   "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
   "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
   "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
   "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
   "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
	
	 $Privilege,
	## The process on which to adjust the privilege. Defaults to the current process.
	$ProcessId = $pid,
	## Switch to disable the privilege, rather than enable it.
	[Switch] $Disable
 )

	 $processHandle = (Get-Process -id $ProcessId).Handle
	 [AdjPriv]::EnablePrivilege($processHandle, $Privilege, $Disable)
	
}

function TrimRegKeyName{
	param([string]$name)
	#remove spaces
	$trimName = $name.Trim()
	#remove our prefix, 00#!_ if already reordered by the script
	$finalName = $trimName -creplace '^[0-9][0-9]#!_', ''
	return $finalName
}

function QueryUserYesNo{
	param([string]$message)
	$title =""
	$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", ""
	$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", ""
	$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
	Write-Host ""
	$result = $host.ui.PromptForChoice($title, $message, $options, 0) 
	Write-Host ""
	switch ($result)
		{
			0 {return $true}
			1 {return $false}
			default {return $false}
		}
}

function CreateOrderFileFunc {
	param ([string]$orderFileName, [string]$dirPath= "." )

	$filePath = Join-Path $dirPath $orderFileName
	$query = Test-Path -Path $filePath -ErrorAction SilentlyContinue
	if( $query) {
		$query = QueryUserYesNo "The file $orderFileName already exists. Do you want to overwrite?"
		if(!$query){
			Write-Host "You answered No. The operation will be aborted." -ForegroundColor Red
			return $false
		}else{
			Write-Host "You answered Yes. The script will continue with Order file creation" -ForegroundColor Green
			Write-Host ""
		}
		Remove-Item -Path $filePath -Force -ErrorAction SilentlyContinue | Out-Null
		if( Test-Path -Path $filePath -ErrorAction SilentlyContinue)  {
			Write-Host "Unable to delete the file ""$orderFileName""!!" -foregroundcolor red
			Write-Host "Please remove the file manualy.. Unable to continue!" -foregroundcolor red
			return $false
		}
	}
	Get-ChildItem $RegPath | ForEach-Object	-Process {
		$origName = $_.PSChildName
		$trimName = TrimRegKeyName -Name $origName
		$trimName | Add-Content -Path $filePath
	}
	if(Test-Path -Path $filePath -ErrorAction SilentlyContinue) {
		$size = (Get-Item $filePath).length
		if($size -gt 0){
			$measures = (Get-Content -Path $filePath | measure -Line)
			$lines = $measures.Lines
			Write-Host "The file ""$orderFileName"" (Size: $size bytes) with $lines items has been succesfully written." -foregroundcolor green	
		}else{
			Write-Host "Warning: The file ""$orderFileName"" has been written but has zero size!!" -foregroundcolor Yellow
		}
		return $true
	}else{
		Write-Host "Error: The file ""$orderFileName"" can't be created!!" -foregroundcolor red
		return $false
	}
}


function GetAclItemPath{
	param($acl)
	if(!$acl){
		return "The ACL is NULL"
	}
	$aclPath = Split-Path -Path $acl.path -NoQualifier
	return $aclPath
}

function WriteACLToSystem {
	param([Parameter(Mandatory=$True,Position=1)] $acl, [string]$errorMessage=$null, [string]$actionInfo=$null )
	try{
		$acl | Set-Acl
	}catch{
		if($errorMessage){
			Write-Host $errorMessage -ForegroundColor Red
		}else{
			$aclPath = GetAclItemPath $acl
			if(!$actionInfo){
				Write-Host "Error: Unable to set New ACL to Registry Item ""$aclPath""" -ForegroundColor Red
			}else{
				Write-Host "Error: $actionInfo - Unable to set New ACL to Registry Item ""$aclPath""" -ForegroundColor Red
			}
		}
		return $false
	}
	return $true
}
#Function for recursive operation to avoid multiple settings od process rights
function SetOwnerToRegKeyInternal{
	param($RegKey, $ownerAccount, [switch]$Recursive)
	$acl = Get-Acl $RegKey
	$acl.SetOwner($ownerAccount)
	if(-Not (WriteACLToSystem $acl -actionInfo "Write new owner")){	return $false }
	if($Recursive){
		#now process all subitems
		Get-ChildItem $RegKey | ForEach-Object {
			$subPath = "Registry::$_"
			SetOwnerToRegKeyInternal -RegKey $subPath -ownerAccount $ownerAccount -Recursive $Recursive
		}
	}
}
function SetOwnerToRegKey {
	param($RegKey, $ownerAccount, [Switch] $Recursive)
	
	begin{
		enable-privilege SeRestorePrivilege | Out-Null
		enable-privilege SeBackupPrivilege | Out-Null
		enable-privilege SeTakeOwnershipPrivilege 	| Out-Null
	}
	process{
		#call internal method with appropriate rights (privileges)
		SetOwnerToRegKeyInternal -RegKey $RegKey -ownerAccount $ownerAccount -Recursive:$Recursive
	}
	end{
		enable-privilege SeRestorePrivilege -Disable | Out-Null
		enable-privilege SeBackupPrivilege -Disable | Out-Null
		enable-privilege SeTakeOwnershipPrivilege -Disable | Out-Null
	}
}

function SetOwnerAsSystem {
	param($RegKey, [Switch] $Recursive)
	$systemUser = New-Object System.Security.Principal.NTAccount("NT AUTHORITY", "SYSTEM")
	if(!$systemUser){
		Write-Host "Error: Unable to create NTACCOUNT for user  SYSTEM" -ForegroundColor Red
		return $false
	}
	SetOwnerToRegKey -RegKey $RegKey -ownerAccount $systemUser -Recursive:$Recursive 
}

function SetOwnerAsAdministrators {
	param($RegKey, [Switch] $Recursive)

	$adminGroup = New-Object System.Security.Principal.NTAccount("Builtin", "Administrators")
	if(!$adminGroup){
		Write-Host "Error: Unable to create NTACCOUNT for group  Builtin\Administrators" -ForegroundColor Red
		return $false
	}
	SetOwnerToRegKey -RegKey $RegKey -ownerAccount $adminGroup -Recursive:$Recursive 
}

function RemoveNonInheritedRights{
	param($acl)

	#get AccessRules without inheritance
	$notinherit  = $acl | Select-Object -ExpandProperty Access | Where-Object { -Not $_.IsInherited }
	$items =$notinherit.length
	Write-Host "Going to remove $items Access Rules..."
	$notinherit | Foreach-Object   { 
		$name = $_.IdentityReference
		Write-Host "Removing rule for user: $name" 
		try {
			$acl.RemoveAccessRule($_) | Out-Null
		}
		catch {
			#Write-Host "Warning: The rule for user: $name was not deleted." 
		}
	}
	#now check if everything is out, we haveproblems with some rules, for example for ALL APPLICATION PACKAGES
	$notinherit  = $acl | Select-Object -ExpandProperty Access | Where-Object { -Not $_.IsInherited }
	$items =$notinherit.length
	if( $items -gt 0){
		Write-Host "Warning: Not all rules ($items) has been removed. Second try with reconstruct RegistryAccessRule objects" -ForegroundColor Yellow
		Write-Host ""
		$items = 0
		$notinherit | Foreach-Object { 
			
			$name = $_.IdentityReference
			$pureName = Split-Path $name -leaf
			$rights = $_.RegistryRights
			$inherit = $_.InheritanceFlags
			$propagate = $_.PropagationFlags
			$action =  $_.AccessControlType
			try{
				$rule = New-Object System.Security.AccessControl.RegistryAccessRule($pureName,$rights,$inherit,$propagate,$action )
			}catch{
				Write-Host "Error: Unable to create RegistryAccessRule for user $purename" -ForegroundColor Red
				$rule = $null
			}
			if ($rule)	{	
				try{
					$acl.RemoveAccessRule($rule)
					Write-Host "   The rule ""$pureName, $rights, $inherit, $propagate, $action"" has been deleted succesfully"
				}catch{
					Write-Host "Error: Unable to delete the rule ""$pureName, $rights, $inherit, $propagate, $action""" -ForegroundColor Red
					$items = $items +1
				}
			}
				
		}
	}

	if( $items -gt 0){
		$notinherit  = $acl | Select-Object -ExpandProperty Access | Where-Object { -Not $_.IsInherited }
		Write-Host "Warning: Unable to remove all rules automatically." -ForegroundColor Yellow
		Write-Host "         Please go to key: ""$RegPath""" -ForegroundColor Yellow
		Write-Host "         and remove these rules WITHOUT INHERITANCE manually:" -ForegroundColor Yellow
		Write-Host ""
		$notinherit | Foreach-Object  { 
			$name = $_.IdentityReference
			$pureName = Split-Path $name -leaf
			$rights = $_.RegistryRights
			$inherit = $_.InheritanceFlags
			$propagate = $_.PropagationFlags
			$action =  $_.AccessControlType
			Write-Host "    Rule: $pureName $rights $inherit $propagate $action" -ForegroundColor Gray
		}
		return $false
	}else{
		Write-Host ""	
		Write-Host "All Rules without inheritance has been removed succesfully." -ForegroundColor Green
	}
	return $true
}



function CheckOrderFile{
	param([string]$orderFileName, [string]$dirPath)
	$orderFilePath = Join-Path $dirPath $orderFileName
	if(-Not (Test-Path -Path $orderFilePath -ErrorAction SilentlyContinue) ) {
		Write-Host "Error: The Order file ""$orderFileName"" doesn't erxist in ""$dirPath"" folder!!" -foregroundcolor red	
		Write-Host "Please create the Order file and try again..."
		return $false	
	}
	return $true
}
function CheckUnprocessedItems{
	param( [System.Object[]]$array )
	$realItems = 0
	for ($i=0; $i -lt $array.length; $i++) {
		if(-Not($array[$i] -eq $dummyItem)){
			$itemName = $array[$i]
			if($realItems -eq 0){
				Write-Host ""
				Write-Host "Warning: Found some unprocessed item(s):" -ForegroundColor Yellow
			}
			$realItems  = $realItems +1
			$num = ($realItems).ToString("00")
			Write-Host "    $num ""$itemName""" -ForegroundColor Yellow
		}
	}
	Write-Host ""
	if($realItems -eq 0){
		Write-Host "All Items from Order file has been processed succesfully." -ForegroundColor Green
	}else{
		Write-Host "Warning: $realItems unprocessed item(s) from Order file has been reported." -ForegroundColor Yellow
	}
	return $realItems
}
function DumpOrderArray{
	param( [System.Object[]]$array, [switch]$JustGreen)
	$items =$array.length
	if($items -gt 15){
		Write-Host "Warning: Windows can process just 15 overlay icons" -foregroundcolor yellow	
		Write-Host "         Only first 15 items will be used by Windows" -foregroundcolor yellow
		if(!$JustGreen){
			Write-Host "         Unused items will be shown in" -foregroundcolor yellow -NoNewline
			Write-Host " RED" -foregroundcolor Red
		}
		Write-Host ""
	}
	for ($i=0; $i -lt $array.length; $i++) {
		$num = ($i+1).ToString("00")
		$itemName = $array[$i]
		if($i -gt 14){
			if($JustGreen){
				return $false
			}
			Write-Host "$num " -ForegroundColor White -NoNewline
			Write-Host  """$itemName""" -ForegroundColor Red
		}else{
			Write-Host "$num " -ForegroundColor White -NoNewline
			Write-Host """$itemName""" -ForegroundColor Green
		}
	}
	if($items -gt 15){
		return $false
	}
	return $true
}
function DumpOrderFile{
	param([string]$orderFileName, [string]$dirPath)
	if (-Not(CheckOrderFile $orderFileName $dirPath)){
		return $false
	}
	$orderFilePath = Join-Path $dirPath $orderFileName
	$array = Get-Content -Path $orderFilePath
	$items =$array.length

	Write-Host "Printing content of the Order Config File..."
	Write-Host ""
	Write-Host "Order file ""$orderFileName"" contains $items items."
	Write-Host ""
	DumpOrderArray $array
}

function ShowRegistryState{

	$array = @()
	Get-ChildItem $RegPath | ForEach-Object {
		$origName = $_.PSChildName
		$array += $origName
	}
	$items =$array.length
	$acl = Get-Acl $RegPath 
	$owner = $acl.Owner
	Write-Host "Owner of the key: $owner" -ForegroundColor Green
	if ($acl.AreAccessRulesProtected){
		Write-Host "Registry key inheritance is disabled" -ForegroundColor Green
	}else{
		Write-Host "Registry key inherits rights from parent" -ForegroundColor Yellow
		
	}
	Write-Host ""
	Write-Host "Printing content of the Registry key for Overlay Icons..."
	Write-Host ""
	Write-Host "Registry contains $items items."
	Write-Host ""
	DumpOrderArray $array
}

function FindItemInArray {
	param( [System.Object[]]$array ,[string]$itemToFind, [switch]$ReplaceWithDummy )

	for ($i=0; $i -lt $array.length; $i++) {
		if( $array[$i]  -eq $itemToFind){
			if($ReplaceWithDummy){
				$array[$i] = $dummyItem
			}
			return $i
		}
	}
	return -1
}
function RegModifyQuery{
	param ([switch]$SupressWarning)

	if(!$SupressWarning){
		Write-Host "Warning: This operation modify the Windows Registry." -ForegroundColor Yellow
		Write-Host "         This can brings unpredictable results to the Windows OS." -ForegroundColor Yellow
		Write-Host "         Author of the script doesn't take any reponsibility for the operation." -ForegroundColor Yellow
		Write-Host "         You provide this operation on your own risk!!" -ForegroundColor Yellow
		Write-Host ""
	}
	$query = QueryUserYesNo "Do you want to proceed with Registry modification?"
	if($query){
		Write-Host "You answered Yes. The script will continue with registry modification" -ForegroundColor Green
	}else{
		Write-Host "You answered No. The operation will be aborted." -ForegroundColor Red
	}
	Write-Host ""
	return $query
}
function InheritanceDesc{
	param($RegPath )
	$acl = Get-Acl $RegPath 
	if ($acl.AreAccessRulesProtected){
		return "Disabled"
	}else{
		return "Enabled"
		
	}
}
function CheckExpectedState
{
	param($expectedOwner, $expectedInheritance)

	$acl = Get-Acl $RegPath 
	$owner = $acl.Owner
	$inheritance = InheritanceDesc $RegPath

	$ownerOk = $owner -eq $expectedOwner
	$inheritanceOK = $inheritance -eq $expectedInheritance
	if (!$ownerOk -or !$inheritanceOK){
		Write-Host "Warning: Seems that the Registry key is already modified by script or another way" -ForegroundColor Yellow
		Write-Host "         Expected state is Inheritance: " -ForegroundColor Yellow -NoNewline
		Write-Host "$expectedInheritance " -ForegroundColor Green -NoNewline
		Write-Host "and Key owner: " -ForegroundColor Yellow -NoNewline
		Write-Host "$expectedOwner" -ForegroundColor Green 
		Write-Host "         Current state is Inheritance:  "-ForegroundColor Yellow -NoNewline
		if($inheritanceOK){
			Write-Host "$expectedInheritance " -ForegroundColor Green -NoNewline
		}else{
			Write-Host "$expectedInheritance " -ForegroundColor Red -NoNewline
		}
		Write-Host "and Key owner: " -ForegroundColor Yellow -NoNewline
		if($ownerOk){
			Write-Host "$owner" -ForegroundColor Green 
		}else{
			Write-Host "$owner" -ForegroundColor Red 
		}
		Write-Host ""

		if (-Not(RegModifyQuery -SupressWarning)){
			return $false
		}
		return $true
	}
	Write-Host "Current registry state fit expectations; Inheritance: " -NoNewline
	Write-Host "$expectedInheritance " -ForegroundColor Green -NoNewline
	Write-Host "and Key owner: "  -NoNewline
	Write-Host "$expectedOwner" -ForegroundColor Green 

	Write-Host "Check of the Registry key state is sucessful." -ForegroundColor Green
	Write-Host "" 
	return $true
}
function LockRegKey
{
	if (-Not(RegModifyQuery)){
		return $false
	}
	#check excpected state
	if (-Not(CheckExpectedState "NT AUTHORITY\SYSTEM"  "Enabled")){
		return $false
	}
	#change owner on Administrators
	SetOwnerAsAdministrators $RegPath -Recursive
	#Disable inheritance on the key
	$acl = Get-Acl $RegPath 
	$acl.SetAccessRuleProtection($true,$true)
	#now set these changes to registry, otherwise we are not able to modify System rights
	if(-Not (WriteACLToSystem $acl -actionInfo "Disable inheritance")){	return $false }
	
	$acl = Get-Acl $RegPath
	#Now change system rights to READ ONLY
	#filter rights for SYSTEM account
	$systemRights  = $acl | Select-Object -ExpandProperty Access | Where-Object { $_.IdentityReference -eq "NT AUTHORITY\SYSTEM" }
	#and remove them
	$systemRights | Foreach-Object   { 
		$name = $_.IdentityReference
		Write-Host "Removing rule for user: $name" 
		try {
			$acl.RemoveAccessRule($_) | Out-Null
		}
		catch {
		}
	}
	#check if deleted
	$systemRights  = $acl | Select-Object -ExpandProperty Access | Where-Object { $_.IdentityReference -eq "NT AUTHORITY\SYSTEM" }
	$items = $systemRights.size
	if( $items -gt 0){
		Write-Host "ERROR: Not all rules for user SYSTEM ($items) has been removed. Second try with reconstruct RegistryAccessRule objects" -ForegroundColor Red
		Write-Host ""
		return $false
	}
	#and now add new system rule with read-only rights
	$rule = New-Object System.Security.AccessControl.RegistryAccessRule("NT AUTHORITY\SYSTEM","ReadKey","ContainerInherit","None","Allow" )
	if(!$rule){
		Write-Host "Error: Unable to create RegistryAccessRule for user  SYSTEM" -ForegroundColor Red
		return $false
	}
	try{
		$acl.SetAccessRule($rule)
	}catch{
		Write-Host "Error: Unable to set ReadKey RegistryAccessRule for user  SYSTEM" -ForegroundColor Red
		return $false
	}
	if(-Not (WriteACLToSystem $acl -actionInfo "Setting SYSTEM ReadOnly")){	return $false }
	Write-Host ""	
	Write-Host "Lock process for Overlay Icons RegKeys succesfully completed." -ForegroundColor Green
	return $true
}
function RestoreKeyOriginalRightsAndInheritance
{
	if (-Not(RegModifyQuery)){
		return $false
	}
	#check excpected state
	if (-Not(CheckExpectedState "BUILTIN\Administrators"  "Disabled")){
		return $false
	}
	#Enable inheritance on the key
	$acl = Get-Acl $RegPath 
	$acl.SetAccessRuleProtection($false,$false)
	#now set these changes to registry, otherwise we are not able to modify Other rights
	if(-Not (WriteACLToSystem $acl -actionInfo "Restore inheritance")){	return $false }
	#now remove rules without inheritance - these rules has been created 
	#during the lock process
	$acl = Get-Acl $RegPath
	$dummy = RemoveNonInheritedRights $acl
	if(-Not (WriteACLToSystem $acl -actionInfo "Remove non-inherit rules")){	return $false }
	#change owner back on SYSTEM
	if(-Not(SetOwnerAsSystem $RegPath -Recursive)){
		return $false
	}
	Write-Host ""	
	Write-Host "Restore process for Overlay Icons RegKeys succesfully completed." -ForegroundColor Green
}

function ModifyRegistryByOrderFile{
	param([string]$orderFileName, [string]$dirPath)

	if (-Not(CheckOrderFile $orderFileName $dirPath)){
		return $false
	}
	$orderFilePath = Join-Path $dirPath $orderFileName
	
	$array = @()
	$x = Get-Content -Path $orderFilePath
	Write-Host ""
	Write-Host "This Order of Items from ""$orderFileName"" will be aplied to the Overlay Icons registry key:"
	Write-Host ""
	$result = DumpOrderArray -array $x -JustGreen
	$items =$x.length
	if(!$result){
		#trip the array
		$items=15
		for ($i=0; $i -lt $items; $i++) {
			$array += $x[$i]
		}
		Write-Host ""
		Write-Host "Warning: The order file ""$orderFileName"" content has been stripped to $items items to reorder." -foregroundcolor Yellow	
	}else{
		$array = $x
		Write-Host ""
		Write-Host "The order file ""$orderFileName"" contains $items items to reorder." -foregroundcolor Green	
	}
	$query = QueryUserYesNo "Do you want to proceed with Re-order processing?"
	if(!$query){
		return $false
	}
	#and now rename the keys
	Get-ChildItem $RegPath | ForEach-Object {
		$origName = $_.PSChildName
		$trimName = TrimRegKeyName $origName
		$index = FindItemInArray $array $trimName -ReplaceWithDummy
		if($index -lt 0){
			Write-Host "Item ""$trimName "" is not in the Order file. Just trim whitespaces" -ForegroundColor Yellow
			if(-Not($origName -eq $trimName)){
				Rename-Item -Path "Registry::$_" -NewName $trimName	
			}
		}else{
			$num = ($index+1).ToString("00")
			$newItemName =" $num#!_$trimName"
			if(-Not($origName -eq $newItemName)){
				Write-Host "The ""$trimName"" has been found in the Order file. Item will be renamed  ""$origName"" --> ""$newItemName""" -ForegroundColor Green
				Rename-Item -Path "Registry::$_" -NewName $newItemName	
			}else{
				Write-Host "The ""$trimName"" has been found in the Order file. Name ""$origName"" is already in required form" -ForegroundColor Green
			}
		}
	}
	$xx = CheckUnprocessedItems $array
	Write-Host ""
	Write-Host "The Re-order process has been finished." -foregroundcolor Green	
	Write-Host ""
}

$orderFileDir = Split-Path $OrderFilePath -parent
$orderFileName = Split-Path $OrderFilePath -leaf

Write-Host ""

switch($Action)
{
	"createOrderFile"    {$xx =CreateOrderFileFunc -orderFileName $orderFileName -dirPath $orderFileDir ;	break	}
	"dumpOrderFile"      {$xx = DumpOrderFile -orderFileName $orderFileName -dirPath $orderFileDir ;  break}
	"showRegistry"       {$xx = ShowRegistryState ; break }
	"reorderRegistry"    {$xx = ModifyRegistryByOrderFile -orderFileName $orderFileName -dirPath $orderFileDir  ;break }
	"lockRegistryKey"    {$xx = LockRegKey; break}
	"restoreRegistryKey" {$xx = RestoreKeyOriginalRightsAndInheritance; break}
	"fixAndLock"{
		$xx = LockRegKey;
		if($xx){
			ModifyRegistryByOrderFile -orderFileName $orderFileName -dirPath $orderFileDir
		}else{
			Write-Host "Error: Lock key operation failed. Uneble to proceed to Re-order" -ForegroundColor Red
		}
		break;
	}
}

