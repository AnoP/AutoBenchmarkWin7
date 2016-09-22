################################ 	2. Local Policies		#########################################
import os
import codecs
import getpass
from _winreg import *
#	https://support.microsoft.com/en-us/kb/243330
#	https://technet.microsoft.com/en-us/library/dn221963(v=ws.11).aspx 
#	http://stackoverflow.com/questions/14606799/what-does-r-do-in-the-following-script
temp = []
f = codecs.open('Data\policies.txt','rb','utf-16')
temp = f.read()
##########	2.1 Audit Policy
##########	2.2 User Rights Assignment
#	2.2.1 Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
def SeTrustedCredManAccessPrivilege():
	if u'SeTrustedCredManAccessPrivilege' not in temp:
		return 'OK'
	return 'WARNING'
#	2.2.2 Ensure 'Access this computer from the network' is set to 'Administrators'
def SeNetworkLogonRight():
	if u'SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551\r\n' in temp:
		return 'NOT GOOD'
	if u'SeNetworkLogonRight = *S-1-5-32-544\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.3 Ensure 'Act as part of the operating system' is set to 'No One'
def SeTcbPrivilege():
	if u'SeTcbPrivilege' not in temp:
		return 'OK'
	return 'WARNING'
#	2.2.4 Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
def SeIncreaseQuotaPrivilege():
	if u'SeIncreaseQuotaPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.5  Ensure 'Allow log on locally' is set to 'Administrators, Users'
def SeInteractiveLogonRight():
	if u'SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-546,*S-1-5-32-551\r\n' in temp:
		return 'NOT GOOD'
	if u'SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.6 Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users' 
def SeRemoteInteractiveLogonRight():
	if u'SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.7 Ensure 'Back up files and directories' is set to 'Administrators'
def SeBackupPrivilege():
	if u'SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551\r\n' in temp:
		return 'NOT GOOD'
	if u'SeBackupPrivilege = *S-1-5-32-544\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.8 Ensure 'Change the system time' is set to 'Administrators, 'LOCAL SERVICE'
def SeSystemtimePrivilege():
	if u'SeSystemtimePrivilege = *S-1-5-19,*S-1-5-32-544\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.9 Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE, Users'
def SeTimeZonePrivilege():
	if u'SeTimeZonePrivilege = *S-1-5-19,*S-1-5-32-544,*S-1-5-32-545\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.10 Ensure 'Create a pagefile' is set to 'Administrators'
def SeCreatePagefilePrivilege():
	if u'SeCreatePagefilePrivilege = *S-1-5-32-544\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.11 Ensure 'Create a token object' is set to 'No One'
def SeCreateTokenPrivilege():
	if u'SeCreateTokenPrivilege' not in temp:
		return 'OK'
	return 'WARNING'
#	2.2.12 Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
def SeCreateGlobalPrivilege():
	if u'SeCreateGlobalPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.13 Ensure 'Create permanent shared objects' is set to 'No One'
def SeCreatePermanentPrivilege():
	if u'SeCreatePermanentPrivilege' not in temp:
		return 'OK'
	return 'WARNING'
#	2.2.14 Ensure 'Create symbolic links' is set to 'Administrators'
def SeCreateSymbolicLinkPrivilege():
	if u'SeCreateSymbolicLinkPrivilege = *S-1-5-32-544\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.15 Ensure 'Debug programs' is set to 'Administrators'
def SeDebugPrivilege():
	if u'SeDebugPrivilege = *S-1-5-32-544\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.16 Ensure 'Deny access to this computer from the network' to include 'Guests, Local account' 
def SeDenyNetworkLogonRight():
	if u'SeDenyNetworkLogonRight = *S-1-5-32-546' in temp:
		return 'NOT GOOD'
	if u'SeDenyNetworkLogonRight = %s,*S-1-5-32-546\r\n'%getpass.getuser() in temp:
		return 'OK'
	return 'WARNING'
#	2.2.17 Ensure 'Deny log on as a batch job' to include 'Guests'
def SeDenyBatchLogonRight():
	if u'SeDenyBatchLogonRight' not in temp:
		return 'NOT GOOD'
	if u'SeDenyBatchLogonRight = *S-1-5-32-546\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.18 Ensure 'Deny log on as a service' to include 'Guests'
def SeDenyServiceLogonRight():
	if u'SeDenyServiceLogonRight' not in temp:
		return 'NOT GOOD'
	if u'SeDenyServiceLogonRight = *S-1-5-32-546\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.19 Ensure 'Deny log on locally' to include 'Guests'
def SeDenyInteractiveLogonRight():
	if u'SeDenyInteractiveLogonRight = *S-1-5-32-546\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.20 Ensure 'Deny log on through Remote Desktop Services' to include 'Guests, Local account'
def SeDenyRemoteInteractiveLogonRight():
	if u'SeDenyRemoteInteractiveLogonRight' not in temp:
		return 'NOT GOOD'
	if u'SeDenyRemoteInteractiveLogonRight = %s,*S-1-5-32-546\r\n'%getpass.getuser() in temp:
		return 'OK'
	return 'WARNING'
#	2.2.21 Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'
def SeEnableDelegationPrivilege():
	if u'SeEnableDelegationPrivilege' not in temp:
		return 'OK'
	return 'WARNING'
#	2.2.22 Ensure 'Force shutdown from a remote system' is set to 'Administrators'
def SeRemoteShutdownPrivilege():
	if u'SeRemoteShutdownPrivilege = *S-1-5-32-544\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.23 Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
def SeAuditPrivilege():
	if u'SeAuditPrivilege = *S-1-5-19,*S-1-5-20\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.24 Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
def SeImpersonatePrivilege():
	if u'SeImpersonatePrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.25 Ensure 'Increase scheduling priority' is set to 'Administrators'
def SeIncreaseBasePriorityPrivilege():
	if u'SeIncreaseBasePriorityPrivilege = *S-1-5-32-544\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.26 Ensure 'Load and unload device drivers' is set to 'Administrators'
def SeLoadDriverPrivilege():
	if u'SeLoadDriverPrivilege = *S-1-5-32-544\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.27 Ensure 'Lock pages in memory' is set to 'No One'
def SeLockMemoryPrivilege():
	if u'SeLockMemoryPrivilege' not in temp:
		return 'OK'
	return 'WARNING'
#	2.2.28 Ensure 'Log on as a batch job' is set to 'Administrators'
def SeBatchLogonRight():
	if u'SeBatchLogonRight = *S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-559\r\n' in temp:
		return 'NOT GOOD'
	if u'SeBatchLogonRight = *S-1-5-32-544\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.29 Ensure 'Log on as a service' is set to 'No One'
def SeServiceLogonRight():
	if u'SeServiceLogonRight = *S-1-5-80-0\r\n' in temp:
		return 'NOT GOOD'
	if u'SeServiceLogonRight' not in temp:
		return 'OK'
	return 'WARNING'
#	2.2.30 Ensure 'Manage auditing and security log' is set to 'Administrators'
def SeSecurityPrivilege():
	if u'SeSecurityPrivilege = *S-1-5-32-544\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.31 Ensure 'Modify an object label' is set to 'No One'
def SeRelabelPrivilege():
	if u'SeRelabelPrivilege' not in temp:
		return 'OK'
	return 'WARNING'
#	2.2.32 Ensure 'Modify firmware environment values' is set to 'Administrators'
def SeSystemEnvironmentPrivilege():
	if u'SeSystemEnvironmentPrivilege = *S-1-5-32-544\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.33 Ensure 'Perform volume maintenance tasks' is set to 'Administrators' 
def SeManageVolumePrivilege():
	if u'SeManageVolumePrivilege = *S-1-5-32-544\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.34 Ensure 'Profile single process' is set to 'Administrators'
def SeProfileSingleProcessPrivilege():
	if u'SeProfileSingleProcessPrivilege = *S-1-5-32-544\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.35 Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost' --> check
def SeSystemProfilePrivilege():
	if u'SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.36 Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
def SeAssignPrimaryTokenPrivilege():
	if u'SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.37 Ensure 'Restore files and directories' is set to 'Administrators'
def SeRestorePrivilege():
	if u'SeRestorePrivilege = *S-1-5-32-544,*S-1-5-32-551\r\n' in temp:
		return 'NOT GOOD'
	if u'SeRestorePrivilege = *S-1-5-32-544\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.38 Ensure 'Shut down the system' is set to 'Administrators, Users'
def SeShutdownPrivilege():
	if u'SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551\r\n' in temp:
		return 'NOT GOOD'
	if u'SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-545\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	2.2.39 Ensure 'Take ownership of files or other objects' is set to 'Administrators'
def SeTakeOwnershipPrivilege():
	if u'SeTakeOwnershipPrivilege = *S-1-5-32-544\r\n' in temp:
		return 'OK'
	return 'WARNING'















	
##########	2.3 Security Options
s = codecs.open('Data\sercurityoptions.txt','rb','utf-16')
tem = s.read()
#	2.3.1 Accounts
#		2.3.1.1 Ensure 'Accounts: Administrator account status' is set to 'Disabled' 
def EnableAdminAccount():
	if u'EnableAdminAccount = 0\r\n' in tem:
		return 'OK'
	return 'WARNING'
#		2.3.1.2 Ensure 'Accounts: Guest account status' is set to 'Disabled'
def EnableGuestAccount():
	if u'EnableGuestAccount = 0\r\n' in tem:
		return 'OK'
	return 'WARNING'
#		2.3.1.3 Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
def LimitBlankPasswordUse():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Lsa', 0, KEY_READ)
		value = (QueryValueEx(key,'LimitBlankPasswordUse')[0])
	except:
		return "NOT CONFIG"
	if value == 1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)
#		2.3.1.4 Configure 'Accounts: Rename administrator account'
def NewAdministratorName():
	if u'NewAdministratorName = "Administrator"\r\n' in tem:
		return 'OK'
	return 'WARNING'
#		2.3.1.5 Configure 'Accounts: Rename guest account'
def NewGuestName():
	if u'NewGuestName = "Guest"\r\n' in tem:
		return 'OK'
	return 'WARNING'

	#	2.3.2 Audit
#		2.3.2.1 Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
def SCENoApplyLegacyAuditPolicy():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Lsa', 0, KEY_READ)
		value = (QueryValueEx(key,'SCENoApplyLegacyAuditPolicy')[0])
	except:
		return "NOT GOOD"
	if value == 1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)
#		2.3.2.2 Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled' 
def crashonauditfail():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Lsa', 0, KEY_READ)
		value = (QueryValueEx(key,'crashonauditfail')[0])
	except:
		return "NOT CONFIG"
	if value == 0 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

	#	2.3.3 DCOM
	#	2.3.4 Devices
#		2.3.4.1 Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators and Interactive Users'
def AllocateDASD():
	if u'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' not in tem:
		return 'NOT GOOD'
	if u'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD=1,"2"\r\n' in tem:
		return 'OK'
	return 'WARNING'
#		2.3.4.2 Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
def AddPrinterDriver():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers', 0, KEY_READ)
		value = (QueryValueEx(key,'AddPrinterDrivers')[0])
	except:
		return "NOT CONFIG"
	if value == 1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	#	2.3.5 Domain controller
	#	2.3.6 Domain member
#		2.3.6.1 Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled' 
def RequireSignOrSeal():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\Netlogon\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'RequireSignOrSeal')[0])
	except:
		return "NOT CONFIG"
	if value == 1 :
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.6.2 Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
def SealSecureChannel():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\Netlogon\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'SealSecureChannel')[0])
	except:
		return "NOT CONFIG"
	if value == 1 :
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.6.3 Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
def SignSecureChannel():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\Netlogon\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'SignSecureChannel')[0])
	except:
		return "NOT CONFIG"
	if value == 1 :
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.6.4 Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
def DisablePasswordChange():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\Netlogon\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'DisablePasswordChange')[0])
	except:
		return "NOT CONFIG"
	if value == 0 :
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.6.5 Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'
def MaximumPasswordAge():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\Netlogon\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'MaximumPasswordAge')[0])
	except:
		return "NOT CONFIG"
	if value <= 30 and value > 0 :
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.6.6 Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
def RequireStrongKey():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\Netlogon\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'RequireStrongKey')[0])
	except:
		return "NOT CONFIG"
	if value == 0 :
		return 'NOT GOOD'
	if value == 1 :
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#	2.3.7 Interactive logon
#		2.3.7.1 Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
def DontDisplayLastUserName():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 0, KEY_READ)
		value = (QueryValueEx(key,'DontDisplayLastUserName')[0])
	except:
		return "NOT CONFIG"
	if value == 0 :
		return 'NOT GOOD'
	if value == 1 :
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.7.2 Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled' 
def DisableCAD():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 0, KEY_READ)
		value = (QueryValueEx(key,'DisableCAD')[0])
	except:
		return 'NOT GOOD'
	if value == 0 :
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.7.3 Configure 'Interactive logon: Message text for users attempting to log on'
def LegalNoticeText():
	if u'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText=7,' in tem:
		return 'NOT GOOD'
#		2.3.7.4 Configure 'Interactive logon: Message title for users attempting to log on'
def LegalNoticeCaption():
	if u'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption=1,""' in tem:
		return 'NOT GOOD'
#		2.3.7.5 Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)'
def CachedLogonsCount():
	t = u'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount=1,"%s"\r\n'
	if t%'10' in tem:
		return 'NOT GOOD'
	if t%'4' in tem or t%'3' in tem or t%'2' in tem or t%'1' in tem or t%'0' in tem:
		return 'OK'
	return 'WARNING'
#		2.3.7.6 Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'
def PasswordExpiryWARNING():
	t = u'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWARNING=4,%s\r\n'
	if t%'14' in tem:
		return 'OK'
	if t%'13' in tem or t%'12' in tem or t%'11' in tem or t%'10' in tem or t%'9' in tem or t%'8' in tem or t%'7' in tem or t%'6' in tem or t%'5' in tem:
		return 'OK'
	return 'WARNING'
#		2.3.7.7 Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher
def ScRemoveOption():
	t = u'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption=1,"%s"\r\n'
	if t%'0' in tem:
		return 'NOT GOOD'
	if t%'1' in tem or t%'2' in tem or t%'3' in tem:
		return 'OK'
	return 'WARNING'
	
	
#	2.3.8 Microsoft network client
#		2.3.8.1 Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
def RequireSecuritySignature():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\LanmanWorkstation\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'RequireSecuritySignature')[0])
	except:
		return 'NOT CONFIG'
	if value == 0 :
		return 'NOT GOOD'
	if value == 1 :
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.8.2 Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
def EnableSecuritySignature():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\LanmanWorkstation\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'EnableSecuritySignature')[0])
	except:
		return 'NOT CONFIG'
	if value == 1 :
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.8.3 Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'
def EnablePlainTextPassword():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\LanmanWorkstation\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'EnablePlainTextPassword')[0])
	except:
		return 'NOT CONFIG'
	if value == 0 :
		return 'OK'
	return 'WARNING'
	CloseKey(key)

	
#	2.3.9 Microsoft network server
#		2.3.9.1 Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'
def autodisconnect():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\LanManServer\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'autodisconnect')[0])
	except:
		return 'NOT CONFIG'
	if value <= 15 or value > 0 :
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.9.2 Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
def RequireSecuritySignatureServer():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\LanManServer\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'requiresecuritysignature')[0])
	except:
		return 'NOT CONFIG'
	if value == 0:
		return 'NOT GOOD'
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.9.3 Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled' 
def EnableSecuritySignatureServer():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\LanManServer\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'enablesecuritysignature')[0])
	except:
		return 'NOT CONFIG'
	if value == 0:
		return 'NOT GOOD'
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.9.4 Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'
def enableforcedlogoff():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\LanManServer\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'enableforcedlogoff')[0])
	except:
		return 'NOT CONFIG'
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.9.5 Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher
def SMBServerNameHardeningLevel():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\LanManServer\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'SMBServerNameHardeningLevel')[0])
	except:
		return 'NOT GOOD'
	if value == 1 or value == 2:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

	
#	2.3.10 Network access
#		2.3.10.1 Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'
def LSAAnonymousNameLookup():
	if u'LSAAnonymousNameLookup = 0\r\n' in tem:
		return 'OK'
	return 'WARNING'
#		2.3.10.2 Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'
def RestrictAnonymousSAM():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Lsa', 0, KEY_READ)
		value = (QueryValueEx(key,'RestrictAnonymousSAM')[0])
	except:
		return 'NOT CONFIG'
	if value == 1 :
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.10.3 Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'
def RestrictAnonymous():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Lsa', 0, KEY_READ)
		value = (QueryValueEx(key,'RestrictAnonymous')[0])
	except:
		return 'NOT CONFIG'
	if value == 0 :
		return 'NOT GOOD'
	if value == 1 :
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.10.4 Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled' 
def disabledomaincreds():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Lsa', 0, KEY_READ)
		value = (QueryValueEx(key,'disabledomaincreds')[0])
	except:
		return 'NOT GOOD'
	if value == 1 :
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.10.5 Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
def EveryoneIncludesAnonymous():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Lsa', 0, KEY_READ)
		value = (QueryValueEx(key,'EveryoneIncludesAnonymous')[0])
	except:
		return 'NOT CONFIG'
	if value == 0 :
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.10.6 Ensure 'Network access: Named Pipes that can be accessed anonymously' is set to 'None' 
def NullSessionPipes():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'NullSessionPipes')[0])
	except:
		return 'NOT CONFIG'
	t = [u'<blank>']
	if (value == t) == 1:
		return 'OK'
	return 'NOT GOOD'
	CloseKey(key)
#		2.3.10.7 Ensure 'Network access: Remotely accessible registry paths'
def AllowedExactPaths():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths', 0, KEY_READ)
		value = (QueryValueEx(key,'Machine')[0])
	except:
		return 'NOT CONFIG'
	t = [u'System\\CurrentControlSet\\Control\\ProductOptions', u'System\\CurrentControlSet\\Control\\Server Applications', u'Software\\Microsoft\\Windows NT\\CurrentVersion']
	if (value == t) == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.10.8 Ensure 'Network access: Remotely accessible registry paths and sub-paths' 
def AllowedPaths():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths', 0, KEY_READ)
		value = (QueryValueEx(key,'Machine')[0])
	except:
		return 'NOT CONFIG'
	t = [u'System\\CurrentControlSet\\Control\\Print\\Printers', u'System\\CurrentControlSet\\Services\\Eventlog', u'Software\\Microsoft\\OLAP Server', u'Software\\Microsoft\\Windows NT\\CurrentVersion\\Print', u'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows', u'System\\CurrentControlSet\\Control\\ContentIndex', u'System\\CurrentControlSet\\Control\\Terminal Server', u'System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig', u'System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration', u'Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib', u'System\\CurrentControlSet\\Services\\SysmonLog']
	if (value == t) == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.10.9 Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
def restrictnullsessaccess():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'restrictnullsessaccess')[0])
	except:
		return 'NOT CONFIG'
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.10.10 Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None' 
def NullSessionShares():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'NullSessionShares')[0])
	except:
		return 'NOT GOOD'
	t = [u'<blank>']
	if (value == t) == 1:
		return 'OK'
	return 'NOT GOOD'
	CloseKey(key)
#		2.3.10.11 Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'
def ForceGuest():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Lsa', 0, KEY_READ)
		value = (QueryValueEx(key,'ForceGuest')[0])
	except:
		return 'NOT CONFIG'
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
	

#	2.3.11 Network security
#		2.3.11.1 Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'
def UseMachineId():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Lsa', 0, KEY_READ)
		value = (QueryValueEx(key,'UseMachineId')[0])
	except:
		return 'NOT GOOD'
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.11.2 Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'
def allownullsessionfallback():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Lsa\MSV1_0', 0, KEY_READ)
		value = (QueryValueEx(key,'allownullsessionfallback')[0])
	except:
		return 'NOT GOOD'
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.11.3 Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'
def AllowOnlineID():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Lsa\pku2u', 0, KEY_READ)
		value = (QueryValueEx(key,'AllowOnlineID')[0])
	except:
		return 'NOT GOOD'
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.11.4 Ensure 'Network Security: Configure encryption types allowed for Kerberos' is set to 'RC4_HMAC_MD5, AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types' 
def SupportedEncryptionTypes():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'SupportedEncryptionTypes')[0])
	except:
		return 'NOT GOOD'
	if value == 2147483644:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.11.5 Ensure 'Network security: Do not store LAN Manager hash alue on next password change' is set to 'Enabled'
def NoLMHash():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Lsa', 0, KEY_READ)
		value = (QueryValueEx(key,'NoLMHash')[0])
	except:
		return 'NOT CONFIG'
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.11.6 Ensure 'Network security: Force logoff when logon hours xpire' is set to 'Enabled' 
def enableforcedlogoff1():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\LanManServer\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'enableforcedlogoff')[0])
	except:
		return 'NOT CONFIG'
	if value == 0:
		return 'OK'
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.11.7 Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM' 
def LmCompatibilityLevel():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Lsa', 0, KEY_READ)
		value = (QueryValueEx(key,'LmCompatibilityLevel')[0])
	except:
		return 'NOT CONFIG'
	if value == 2:
		return 'NOT GOOD'
	if value == 5:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.11.8 Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
def LDAPClientIntegrity():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\LDAP', 0, KEY_READ)
		value = (QueryValueEx(key,'LDAPClientIntegrity')[0])
	except:
		return 'NOT CONFIG'
	if value == 1 or value == 2:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.11.9  Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption' 
def NTLMMinClientSec():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Lsa\MSV1_0', 0, KEY_READ)
		value = (QueryValueEx(key,'NTLMMinClientSec')[0])
	except:
		return 'NOT CONFIG'
	if value == 536870912:
		return 'NOT GOOD'
	if value == 537395200:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.11.10 Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
def NTLMMinServerSec():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Lsa\MSV1_0', 0, KEY_READ)
		value = (QueryValueEx(key,'NTLMMinServerSec')[0])
	except:
		return 'NOT CONFIG'
	if value == 536870912:
		return 'NOT GOOD'
	if value == 537395200:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

	
	
#	2.3.12 Recovery console
#	2.3.13 Shutdown
#	2.3.14 System cryptography
#		2.3.14.1 Ensure 'System cryptography: Force strong key protection for user keys stored on the computer' is set to 'User is prompted what-does-r-do-in-the-following-scrip the key is first used' or higher 
def ForceKeyProtection():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Cryptography', 0, KEY_READ)
		value = (QueryValueEx(key,'ForceKeyProtection')[0])
	except:
		return 'NOT GOOD'
	if value == 1 or value == 2:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#	2.3.15 System objects
#		2.3.15.1 Ensure 'System objects: Require case insensitivity for non Windows subsystems' is set to 'Enabled'
def ObCaseInsensitive():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Session Manager\Kernel', 0, KEY_READ)
		value = (QueryValueEx(key,'ObCaseInsensitive')[0])
	except:
		return 'NOT CONFIG'
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.15.2 Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled' 
def ProtectionMode():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Session Manager', 0, KEY_READ)
		value = (QueryValueEx(key,'ProtectionMode')[0])
	except:
		return 'NOT CONFIG'
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#	2.3.16 System settings
#		2.3.16.1 Ensure 'System settings: Optional subsystems' is set to 'Defined: (blank)'
def Optional():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Control\Session Manager\Subsystems', 0, KEY_READ)
		value = (QueryValueEx(key,'Optional')[0])
	except:
		return 'NOT CONFIG'
	if (value == [u'Posix']) == 1:
		return 'NOT GOOD'
	if (value == [u'Defined: (blank)']) == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#	2.3.17 User Account Control
#		2.3.17.1 Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'
def FilterAdministratorToken():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 0, KEY_READ)
		value = (QueryValueEx(key,'FilterAdministratorToken')[0])
	except:
		return 'NOT CONFIG'
	if value == 0:
		return 'NOT GOOD'
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.17.2 Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled' 
def EnableUIADesktopToggle():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 0, KEY_READ)
		value = (QueryValueEx(key,'EnableUIADesktopToggle')[0])
	except:
		return 'NOT CONFIG'
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.17.3 Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'
def ConsentPromptBehaviorAdmin():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 0, KEY_READ)
		value = (QueryValueEx(key,'ConsentPromptBehaviorAdmin')[0])
	except:
		return 'NOT CONFIG'
	if value == 5:
		return 'NOT GOOD'
	if value == 2:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.17.4 Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'
def ConsentPromptBehaviorUser():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 0, KEY_READ)
		value = (QueryValueEx(key,'ConsentPromptBehaviorUser')[0])
	except:
		return 'NOT CONFIG'
	if value == 3:
		return 'NOT GOOD'
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.17.5 Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'
def EnableInstallerDetection():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 0, KEY_READ)
		value = (QueryValueEx(key,'EnableInstallerDetection')[0])
	except:
		return 'NOT CONFIG'
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.17.6 Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'
def EnableSecureUIAPaths():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 0, KEY_READ)
		value = (QueryValueEx(key,'EnableSecureUIAPaths')[0])
	except:
		return 'NOT CONFIG'
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.17.7 Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
def EnableLUA():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 0, KEY_READ)
		value = (QueryValueEx(key,'EnableLUA')[0])
	except:
		return 'NOT CONFIG'
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.17.8 Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'
def PromptOnSecureDesktop():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 0, KEY_READ)
		value = (QueryValueEx(key,'PromptOnSecureDesktop')[0])
	except:
		return 'NOT CONFIG'
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
#		2.3.17.9 Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled' 
def EnableVirtualization():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 0, KEY_READ)
		value = (QueryValueEx(key,'EnableVirtualization')[0])
	except:
		return 'NOT CONFIG'
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)