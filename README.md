# OverlayIconFix
This script has been created to solve a nightmare in Windows Overlay Icons handling. It allows to protect the TortoiseGIT or SVN Icons against Dropbox

Because the Windows OS is able to process just 15 overlay icons at one time. Many programs pushed own icons on top of the Overlay Icon records list at all costs. The Dropbox is famous about that and even many users complain to Dropbox that they need to use different icons, for Git or SVN for example and Dropbox is not priority for them, Dropbox ignore these voices and still push all own 8 icons on top of the list.

Because programs behavior has been moved to dynamic and regular updates of Icon records, easy old fix to just rename some keys in the Windows registry doesn’t work. After reboot, Dropbox is on top again… To preserve order which fit your needs, you have to disable Access Rights inheritance, change key Owner and remove write rights to these keys for SYSTEM user. It’s not easy task and for many users is beyond the scope of their knowledge. 

To automate this is very annoying process which have to be done very often I have written a script to automate the process. It is written in **PowerShell**, because this is present on all modern computers with Windows and then is just enough to copy the script and run it.

### How to use a script in several steps:
1.	Copy the script to some folder, Start PowerShell command prompt as Administrator and change Working directory to this folder.
2.	Enable PowerShell execution on the computer, because by default is not allowed to run unsigned scripts:  **Set-ExecutionPolicy Unrestricted**
3.	Run the script with parameter **createOrderFile**: *.\overlayIconFix.ps1 createOrderFile < -OrderFilePath “path to your file”>*. It generates file *“orderFile.txt”* in the same folder where script is copied, or if you used **-OrderFilePath** parameter then on specified location. The file is generated based on your current Overlay Icons Registry key content.
4.	Open the previously generated file *“orderFile.txt”* and modify line orders to fit your needs. First 15 lines have to contain Icon record names which will be shown. Then select them carefully. You can find my order file in the repo – it’s focused on TortoiseGit usage. After you finished your re-ordering, save the file.
5.	Now run the script again with parameter **fixAndLock**:  *.\overlayIconFix.ps1 createOrderFile < -OrderFilePath “path to your file”>*. The command change owner and rights for the Overlay Icons Registry key to protect it against unwanted modifications and then re-order key content to reflect content of the *“orderFile.txt”.*
6. Set PowerShell Execution Policy back to default values **Set-ExecutionPolicy Default**
7.	Restart the Explorer or reboot the computer to enjoy Overlay Icons which you really need, without Dropbox or other abuse.


Because owner of the Registry key is set to **Administrators** group, I do not expect problems during program updates or installation of new programs with Overlay Icons. But to avoid problems, you can unlock the key temporarily by call the script with command **unlockRegistryKey** and after all necessary actions you can lock it again by command **lockRegistryKey**. Or you can completely remove all modifications provided by the script in one shoot with the **unlockAndRestore** command. It removes re-ordering prefix from Registry sub-keys and remove protection from the Key. Then except some names orginally prefixed with spaces to be first on the list (DropBox), the Registry key content and rights will be same as before the script fix has been fired.

Please let me know if you find that some other applications avoid this script protection or some records can’t by modified by this script. I’ll try to update script to reflect these changes.

### Script parameters and usage in details

The script accepts two parameters. First parameter **Action** is mandatory, second, **OrderFilePath** is optional.

* **Action**  
Specifies required action: createOrderFile, dumpOrderFile, showRegistry, reorderRegistry lockRegistryKey, unlockRegistryKey, fixAndLock, restoreRegistryKeys unlockAndRestore
 
* **OrderFilePath**    
Specifies path to Order file. This file specifies required order of Overlay Icon Records in the Registry. If empty, script expects the file "orderFile.txt" in current directory. The parameter make sense for createOrderFile, dumpOrderFile, fixAndLock and reorderRegistry commands.
    

#### Supported actions in detail:

* **showRegistry**:         *.\overlayIconFix.ps1 showRegistry*    
          Show current content of the Overlay Icons registry Key. This piece of information allow to check currently available Overlay Icon Items and check their order.

* **createOrderFile**:      *.\overlayIconFix.ps1 createOrderFile -OrderFilePath X:\order.txt*   
		Creates Order file from current Registry content. You can then modify order of items in the file to fit your needs.

* **fixAndLock**:           *.\overlayIconFix.ps1 fixAndLock -OrderFilePath X:\order.txt*    
    This is the base operation of the script. It Locks the registry key with Overlay Icon Records against modifications. This is necessary to block Dropbox or other simmilar services to provide own reordering of the Icon records. Then script re-order Icon records to same order as specified in the Order file.	In details, it executes lockRegistryKey and reorderRegistry operations in one run.

* **dumpOrderFile**:        *.\overlayIconFix.ps1 dumpOrderFile X:\order.txt*    
		Dumps content of the specified Order file to check if order of items is correct.

* **lockRegistryKey**:      *.\overlayIconFix.ps1 lockRegistryKey*   
		Locks the registry key with Overlay Icon Records against modifications from other processes running under SYSTEM account. It block Dropbox or other simmilar services to provide own reordering of the Icon records. In details it changes owner of the Key and Sub-Keys to Administrators group, disable Access Right Inheritance on the key and then remove Write rights for the SYSTEM account. 

* **reorderRegistry**:      *.\overlayIconFix.ps1 reorderRegistry -OrderFilePath X:\order.txt*   
		Re-orders Icon records to same order as specified in the Order file. Can be used many times to organize Icons to required order. But without lock it can be change by	other service easily as for exaple DropBox does. 

* **unlockRegistryKey**:    *.\overlayIconFix.ps1 unlockRegistryKey*   
		Remove Lock from the Overlay Icons Registry key and restore it to original state. Returns ownership to the SYSTEM account, enable inheritance again and restore access rights to the key to original values.

* **restoreRegistryKeys**:  *.\overlayIconFix.ps1 restoreRegistryKeys*   
		Restore Icon record names under the Overlay Icons Registry to original states. Removes script prefix and unused spaces. Order of item snow be driven by alphabetical order of their names

* **unlockAndRestore**:     *.\overlayIconFix.ps1 unlockAndRestore*    
		This action joins unlockRegistryKey and restoreRegistryKeys to one action.


### DropBox Icons Identifiers

Because DropBox doesn't use self-explanatory Overlay Icons identifiers here is list of identifiers with explanation what each Item ans it's related Icon means. It's copied from some web resources:

 1. **DropboxExt01** - Synced! - (green)
 2. **DropboxExt02** - Sync in progress (blue)
 3. **DropboxExt03** - Locked: Synced! (green + lock)
 4. **DropboxExt04** - Locked: Sync in progress (blue + lock)
 5. **DropboxExt05** - Sync not happening (red X)
 6. **DropboxExt06** - Locked: Sync not happening (red X + Lock)
 7. **DropboxExt07** - A file or folder isn't syncing (gray minus)
 8. **DropboxExt08** - Locked: A file or folder isn't syncing (gray minus + Lock)

