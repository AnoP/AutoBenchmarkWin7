import sys
import os
import os.path
sys.path.insert(0,'%s\Module'%os.getcwd())
import shutil
import ctypes
class disable_file_system_redirection:
    _disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
    _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection
    def __enter__(self):
        self.old_value = ctypes.c_long()
        self.success = self._disable(ctypes.byref(self.old_value))
    def __exit__(self, type, value, traceback):
        if self.success:
            self._revert(self.old_value)
disable_file_system_redirection().__enter__()
path = r'C:\\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv'
if os.path.exists(path):
	shutil.copy2(path, '%s\Data'%os.getcwd())
else :
	fi = open("Data\audit.csv","r")
# Create GPO export to check value
def ReportGPO():
	os.popen('secedit /export /areas USER_RIGHTS /cfg %s\Data\policies.txt'%os.getcwd())
	os.popen('secedit /export /areas SECURITYPOLICY /cfg %s\Data\sercurityoptions.txt'%os.getcwd())
ReportGPO()
import platform
import getpass
import time
import LocalPolicies
import AccountPolicies
import AdministrativeTemplatesComputer
import AdministrativeTemplatesUser
import FirewallDomainProfile
import FirewallPrivateProfile
import FirewallPublicProfile
import AdvancedAuditPolicyConfiguration
import CountWarning
import report

def SystemInfomation():
	time.sleep(0.5)
	print '\t','_'*100,'\n'
	print '\t\t\t\t\t','#'*25,'\n','\t\t\t\t\t##  System Infomation  ##','\n','\t\t\t\t\t','#'*25
	print '\t','_'*100
	print '\n\tOS Name :\t\t',platform.system(),platform.release(),platform.win32_ver()[2]
	print '\tOS Version :\t\t',platform.version()
	print '\tSystem Name :\t\t',platform.uname()[1]
	print '\tUser Name :\t\t%s/%s'%(platform.uname()[1],getpass.getuser())
	print '\tMachine Type :\t\t',platform.machine()
	print '\tProcessor Name :\t',platform.processor()
	print '\t','_'*100
#	1. Account Policies
def AccPolicies():
	print '\n1. Account Policies'
	time.sleep(0.5)
	print '%s1.1 Password Policy'%(' '*3)
	print '%s+ Enforce password history'%(' '*7),'\t\t\t\t\t\t[%s]'%AccountPolicies.PasswordHistorySize()
	print '%s+ Maximum password age'%(' '*7),'\t\t\t\t\t\t\t[%s]'%AccountPolicies.MaximumPasswordAge()
	print '%s+ Minimum password age'%(' '*7),'\t\t\t\t\t\t\t[%s]'%AccountPolicies.MinimumPasswordAge()
	print '%s+ Minimum password length'%(' '*7),'\t\t\t\t\t\t[%s]'%AccountPolicies.MinimumPasswordLength()
	print '%s+ Password must meet complexity requirements'%(' '*7),'\t\t\t\t[%s]'%AccountPolicies.PasswordComplexity()
	print '%s+ Store passwords using reversible encryption'%(' '*7),'\t\t\t\t[%s]'%AccountPolicies.ClearTextPassword()
	
	time.sleep(0.5)
	print '\n%s1.2 Account Lockout Policy'%(' '*3)
	print '%s+ Account lockout duration'%(' '*7),'\t\t\t\t\t\t[%s]'%AccountPolicies.LockoutDuration()
	print '%s+ Account lockout threshold'%(' '*7),'\t\t\t\t\t\t[%s]'%AccountPolicies.LockoutBadCount()
	print '%s+ Reset account lockout counter after'%(' '*7),'\t\t\t\t\t[%s]'%AccountPolicies.ResetLockoutCount()
#	2. Local Policies
def LocaPolicies():
	print '\t','_'*60,'\n\n2. Local Policies'
	
	time.sleep(0.5)
	print '\n%s2.1 Audit Policy'%(' '*3),'\t\t\t\t\t\t\t\t[Default]'
	
	time.sleep(0.5)
	print '\n%s2.2 User Rights Assignment'%(' '*3)
	print '%s+ Access Credential Manager as a trusted caller'%(' '*7),'\t\t\t\t[%s]'%LocalPolicies.SeTrustedCredManAccessPrivilege()
	print '%s+ Access this computer from the network'%(' '*7),'\t\t\t\t\t[%s]'%LocalPolicies.SeNetworkLogonRight()
	print '%s+ Act as part of the operating system'%(' '*7),'\t\t\t\t\t[%s]'%LocalPolicies.SeTcbPrivilege()
	print '%s+ Adjust memory quotas for a process'%(' '*7),'\t\t\t\t\t[%s]'%LocalPolicies.SeIncreaseQuotaPrivilege()
	print '%s+ Allow log on locally'%(' '*7),'\t\t\t\t\t\t\t[%s]'%LocalPolicies.SeInteractiveLogonRight()
	print '%s+ Allow log on through Remote Desktop Services'%(' '*7),'\t\t\t\t[%s]'%LocalPolicies.SeRemoteInteractiveLogonRight()
	print '%s+ Back up files and directories'%(' '*7),'\t\t\t\t\t\t[%s]'%LocalPolicies.SeBackupPrivilege()
	print '%s+ Change the system time'%(' '*7),'\t\t\t\t\t\t[%s]'%LocalPolicies.SeSystemtimePrivilege()
	print '%s+ Change the time zone'%(' '*7),'\t\t\t\t\t\t\t[%s]'%LocalPolicies.SeTimeZonePrivilege()
	print '%s+ Create a pagefile'%(' '*7),'\t\t\t\t\t\t\t[%s]'%LocalPolicies.SeCreatePagefilePrivilege()
	print '%s+ Create a token object'%(' '*7),'\t\t\t\t\t\t\t[%s]'%LocalPolicies.SeCreateTokenPrivilege()
	print '%s+ Create global objects'%(' '*7),'\t\t\t\t\t\t\t[%s]'%LocalPolicies.SeCreateGlobalPrivilege()
	print '%s+ Create permanent shared objects'%(' '*7),'\t\t\t\t\t[%s]'%LocalPolicies.SeCreatePermanentPrivilege()
	print '%s+ Create symbolic links'%(' '*7),'\t\t\t\t\t\t\t[%s]'%LocalPolicies.SeCreateSymbolicLinkPrivilege()
	print '%s+ Debug programs'%(' '*7),'\t\t\t\t\t\t\t[%s]'%LocalPolicies.SeDebugPrivilege()
	print '%s+ Deny access to this computer from the network'%(' '*7),'\t\t\t\t[%s]'%LocalPolicies.SeDenyNetworkLogonRight()
	print '%s+ Deny log on as a batch job'%(' '*7),'\t\t\t\t\t\t[%s]'%LocalPolicies.SeDenyBatchLogonRight()
	print '%s+ Deny log on as a service'%(' '*7),'\t\t\t\t\t\t[%s]'%LocalPolicies.SeDenyServiceLogonRight()
	print '%s+ Deny log on locally'%(' '*7),'\t\t\t\t\t\t\t[%s]'%LocalPolicies.SeDenyInteractiveLogonRight()
	print '%s+ Deny log on through Remote Desktop Services'%(' '*7),'\t\t\t\t[%s]'%LocalPolicies.SeDenyRemoteInteractiveLogonRight()
	print '%s+ Enable computer and user accounts to be trusted for delegation'%(' '*7),'\t[%s]'%LocalPolicies.SeEnableDelegationPrivilege()
	print '%s+ Force shutdown from a remote system'%(' '*7),'\t\t\t\t\t[%s]'%LocalPolicies.SeRemoteShutdownPrivilege()
	print '%s+ Generate security audits'%(' '*7),'\t\t\t\t\t\t[%s]'%LocalPolicies.SeAuditPrivilege()
	print '%s+ Impersonate a client after authentication'%(' '*7),'\t\t\t\t[%s]'%LocalPolicies.SeImpersonatePrivilege()
	print '%s+ Increase scheduling priority'%(' '*7),'\t\t\t\t\t\t[%s]'%LocalPolicies.SeIncreaseBasePriorityPrivilege()
	print '%s+ Load and unload device drivers'%(' '*7),'\t\t\t\t\t[%s]'%LocalPolicies.SeLoadDriverPrivilege()
	print '%s+ Lock pages in memory'%(' '*7),'\t\t\t\t\t\t\t[%s]'%LocalPolicies.SeLockMemoryPrivilege()
	print '%s+ Log on as a batch job'%(' '*7),'\t\t\t\t\t\t\t[%s]'%LocalPolicies.SeBatchLogonRight()
	print '%s+ Log on as a service'%(' '*7),'\t\t\t\t\t\t\t[%s]'%LocalPolicies.SeServiceLogonRight()
	print '%s+ Manage auditing and security log'%(' '*7),'\t\t\t\t\t[%s]'%LocalPolicies.SeSecurityPrivilege()
	print '%s+ Modify an object label'%(' '*7),'\t\t\t\t\t\t[%s]'%LocalPolicies.SeRelabelPrivilege()
	print '%s+ Modify firmware environment values'%(' '*7),'\t\t\t\t\t[%s]'%LocalPolicies.SeSystemEnvironmentPrivilege()
	print '%s+ Perform volume maintenance tasks'%(' '*7),'\t\t\t\t\t[%s]'%LocalPolicies.SeManageVolumePrivilege()
	print '%s+ Profile single process'%(' '*7),'\t\t\t\t\t\t[%s]'%LocalPolicies.SeProfileSingleProcessPrivilege()
	print '%s+ Profile system performance'%(' '*7),'\t\t\t\t\t\t[%s]'%LocalPolicies.SeSystemProfilePrivilege()
	print '%s+ Replace a process level token'%(' '*7),'\t\t\t\t\t\t[%s]'%LocalPolicies.SeAssignPrimaryTokenPrivilege()
	print '%s+ Restore files and directories'%(' '*7),'\t\t\t\t\t\t[%s]'%LocalPolicies.SeRestorePrivilege()
	print '%s+ Shut down the system'%(' '*7),'\t\t\t\t\t\t\t[%s]'%LocalPolicies.SeShutdownPrivilege()
	print '%s+ Take ownership of files or other objects'%(' '*7),'\t\t\t\t[%s]'%LocalPolicies.SeTakeOwnershipPrivilege()

	time.sleep(0.5)
	print '\n%s2.3 Security Options'%(' '*3)	
	time.sleep(0.25)
	print '%s+ Accounts'%(' '*7)
	print '%s* Administrator account status'%(' '*11),'\t\t\t\t\t[%s]'%LocalPolicies.EnableAdminAccount()
	print '%s* Guest account status'%(' '*11),'\t\t\t\t\t\t[%s]'%LocalPolicies.EnableGuestAccount()
	print '%s* Limit local account use of blank passwords to console logon only'%(' '*11),'\t[%s]'%LocalPolicies.LimitBlankPasswordUse()
	print '%s* Rename administrator account'%(' '*11),'\t\t\t\t\t[%s]'%LocalPolicies.NewAdministratorName()
	print '%s* Rename guest account'%(' '*11),'\t\t\t\t\t\t[%s]'%LocalPolicies.NewGuestName()
	time.sleep(0.25)
	print '%s+ Audit'%(' '*7)
	print '%s* Force AP subcategory settings to override AP category settings'%(' '*11),'\t[%s]'%LocalPolicies.SCENoApplyLegacyAuditPolicy()
	print '%s* Shut down system immediately if unable to log security audits'%(' '*11),'\t[%s]'%LocalPolicies.crashonauditfail()
	time.sleep(0.25)
	print '%s+ DCOM'%(' '*7),'\t\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Devices'%(' '*7)
	print '%s* Allowed to format and eject removable media'%(' '*11),'\t\t\t[%s]'%LocalPolicies.AllocateDASD()
	print '%s* Prevent users from installing printer drivers'%(' '*11),'\t\t\t[%s]'%LocalPolicies.AddPrinterDriver()
	time.sleep(0.25)
	print '%s+ Domain controller'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Domain member'%(' '*7)
	print '%s* Digitally encrypt or sign secure channel data (always)'%(' '*11),'\t\t[%s]'%LocalPolicies.RequireSignOrSeal()
	print '%s* Digitally encrypt secure channel data (when possible)'%(' '*11),'\t\t[%s]'%LocalPolicies.SealSecureChannel()
	print '%s* Digitally sign secure channel data (when possible)'%(' '*11),'\t\t[%s]'%LocalPolicies.SignSecureChannel()
	print '%s* Disable machine account password changes'%(' '*11),'\t\t\t\t[%s]'%LocalPolicies.DisablePasswordChange()
	print '%s* Maximum machine account password age'%(' '*11),'\t\t\t\t[%s]'%LocalPolicies.MaximumPasswordAge()
	print '%s* Require strong (Windows 2000 or later) session key'%(' '*11),'\t\t[%s]'%LocalPolicies.RequireStrongKey()
	time.sleep(0.25)
	print '%s+ Interactive logon'%(' '*7)
	print '%s* Do not display last user name'%(' '*11),'\t\t\t\t\t[%s]'%LocalPolicies.DontDisplayLastUserName()
	print '%s* Do not require CTRL+ALT+DEL'%(' '*11),'\t\t\t\t\t[%s]'%LocalPolicies.DisableCAD()
	print '%s* Message text for users attempting to log on'%(' '*11),'\t\t\t[%s]'%LocalPolicies.LegalNoticeText()
	print '%s* Message title for users attempting to log on'%(' '*11),'\t\t\t[%s]'%LocalPolicies.LegalNoticeCaption()
	print '%s* Number of previous logons to cache'%(' '*11),'\t\t\t\t[%s]'%LocalPolicies.CachedLogonsCount()
	print '%s* Prompt user to change password before expiration'%(' '*11),'\t\t\t[%s]'%LocalPolicies.PasswordExpiryWARNING()
	print '%s* Smart card removal behavior'%(' '*11),'\t\t\t\t\t[%s]'%LocalPolicies.ScRemoveOption()
	time.sleep(0.25)
	print '%s+ Microsoft network client'%(' '*7)
	print '%s* Digitally sign communications (always)'%(' '*11),'\t\t\t\t[%s]'%LocalPolicies.RequireSecuritySignature()
	print '%s* Digitally sign communications (if server agrees)'%(' '*11),'\t\t\t[%s]'%LocalPolicies.EnableSecuritySignature()
	print '%s* Send unencrypted password to third-party SMB servers'%(' '*11),'\t\t[%s]'%LocalPolicies.EnablePlainTextPassword()
	time.sleep(0.25)
	print '%s+ Microsoft network server'%(' '*7)
	print '%s* Amount of idle time required before suspending session'%(' '*11),'\t\t[%s]'%LocalPolicies.autodisconnect()
	print '%s* Digitally sign communications (always)'%(' '*11),'\t\t\t\t[%s]'%LocalPolicies.RequireSecuritySignatureServer()
	print '%s* Digitally sign communications (if client agrees)'%(' '*11),'\t\t\t[%s]'%LocalPolicies.EnableSecuritySignatureServer()
	print '%s* Disconnect clients when logon hours expire'%(' '*11),'\t\t\t[%s]'%LocalPolicies.enableforcedlogoff()
	print '%s* Server SPN target name validation level'%(' '*11),'\t\t\t\t[%s]'%LocalPolicies.SMBServerNameHardeningLevel()
	time.sleep(0.25)
	print '%s+ Network access'%(' '*7)
	print '%s* Allow anonymous SID/Name translation'%(' '*11),'\t\t\t\t[%s]'%LocalPolicies.LSAAnonymousNameLookup()
	print '%s* Do not allow anonymous enumeration of SAM accounts'%(' '*11),'\t\t[%s]'%LocalPolicies.RestrictAnonymousSAM()
	print '%s* Do not allow anonymous enumeration of SAM accounts and shares'%(' '*11),'\t[%s]'%LocalPolicies.RestrictAnonymous()
	print '%s* Do not allow storage of pass and cred for network authentication'%(' '*11),'\t[%s]'%LocalPolicies.disabledomaincreds()
	print '%s* Let Everyone permissions apply to anonymous users'%(' '*11),'\t\t\t[%s]'%LocalPolicies.EveryoneIncludesAnonymous()
	print '%s* Named Pipes that can be accessed anonymously'%(' '*11),'\t\t\t[%s]'%LocalPolicies.NullSessionPipes()
	print '%s* Remotely accessible registry paths'%(' '*11),'\t\t\t\t[%s]'%LocalPolicies.AllowedExactPaths()
	print '%s* Remotely accessible registry paths and sub-paths'%(' '*11),'\t\t\t[%s]'%LocalPolicies.AllowedPaths()
	print '%s* Restrict anonymous access to Named Pipes and Shares'%(' '*11),'\t\t[%s]'%LocalPolicies.restrictnullsessaccess()
	print '%s* Shares that can be accessed anonymously'%(' '*11),'\t\t\t\t[%s]'%LocalPolicies.NullSessionShares()
	print '%s* Sharing and security model for local accounts'%(' '*11),'\t\t\t[%s]'%LocalPolicies.ForceGuest()
	time.sleep(0.25)
	print '%s+ Network security'%(' '*7)
	print '%s* Allow Local System to use computer identity for NTLM'%(' '*11),'\t\t[%s]'%LocalPolicies.UseMachineId()
	print '%s* Allow LocalSystem NULL session fallback'%(' '*11),'\t\t\t\t[%s]'%LocalPolicies.allownullsessionfallback()
	print '%s* Allow PKU2U authentication requests to Com to use onl identities'%(' '*11),'\t[%s]'%LocalPolicies.AllowOnlineID()
	print '%s* Configure encryption types allowed for Kerberos'%(' '*11),'\t\t\t[%s]'%LocalPolicies.SupportedEncryptionTypes()
	print '%s* Do not store LAN Manager hash alue on next password change'%(' '*11),'\t[%s]'%LocalPolicies.NoLMHash()
	print '%s* Force logoff when logon hours xpire'%(' '*11),'\t\t\t\t[%s]'%LocalPolicies.enableforcedlogoff1()
	print '%s* LAN Manager authentication level'%(' '*11),'\t\t\t\t\t[%s]'%LocalPolicies.LmCompatibilityLevel()
	print '%s* LDAP client signing requirements'%(' '*11),'\t\t\t\t\t[%s]'%LocalPolicies.LDAPClientIntegrity()
	print '%s* Minimum session security for NTLM SSP based (+ seRPC) clients'%(' '*11),'\t[%s]'%LocalPolicies.NTLMMinClientSec()
	print '%s* Minimum session security for NTLM SSP based (+ seRPC) servers'%(' '*11),'\t[%s]'%LocalPolicies.NTLMMinServerSec()
	time.sleep(0.25)
	print '%s+ Recovery console'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Shutdown'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ System cryptography'%(' '*7)
	print '%s* Force strong key protection for user keys stored on the computer'%(' '*11),'\t[%s]'%LocalPolicies.ForceKeyProtection()
	time.sleep(0.25)
	print '%s+ System objects'%(' '*7)
	print '%s* Require case insensitivity for non Windows subsystems'%(' '*11),'\t\t[%s]'%LocalPolicies.ObCaseInsensitive()
	print '%s* Strengthen default permissions of internal system objects'%(' '*11),'\t\t[%s]'%LocalPolicies.ProtectionMode()
	time.sleep(0.25)
	print '%s+ System settings'%(' '*7)
	print '%s* Optional subsystems'%(' '*11),'\t\t\t\t\t\t[%s]'%LocalPolicies.Optional()
	time.sleep(0.25)
	print '%s+ User Account Control'%(' '*7)
	print '%s* Admin Approval Mode for the Built-in Administrator account'%(' '*11),'\t[%s]'%LocalPolicies.FilterAdministratorToken()
	print '%s* Allow UIAccess applications'%(' '*11),'\t\t\t\t\t[%s]'%LocalPolicies.EnableUIADesktopToggle()
	print '%s* Behavior of the elevation prompt for admin ( Admin Approval Mode)'%(' '*11),'\t[%s]'%LocalPolicies.ConsentPromptBehaviorAdmin()
	print '%s* Behavior of the elevation prompt for standard users'%(' '*11),'\t\t[%s]'%LocalPolicies.ConsentPromptBehaviorUser()
	print '%s* Detect application installations and prompt for elevation'%(' '*11),'\t\t[%s]'%LocalPolicies.EnableInstallerDetection()
	print '%s* Only elevate UIAccess App that are installed in secure locations'%(' '*11),'\t[%s]'%LocalPolicies.EnableSecureUIAPaths()
	print '%s* Run all administrators in Admin Approval Mode'%(' '*11),'\t\t\t[%s]'%LocalPolicies.EnableLUA()
	print '%s* Switch to the secure desktop when prompting for elevation'%(' '*11),'\t\t[%s]'%LocalPolicies.PromptOnSecureDesktop()
	print '%s* Virtualize file and registry write failures to per-user locations'%(' '*11),'\t[%s]'%LocalPolicies.EnableVirtualization()
#	3. Event Log
def Eventlog():
	time.sleep(0.5)
	print '\t','_'*60,'\n\n3. Event Log\t\t\t\t\t\t\t\t\t[Default]'
#	4. Restricted Groups
def RestrictedGroups():
	time.sleep(0.5)
	print '\t','_'*60,'\n\n4. Restricted Groups\t\t\t\t\t\t\t\t[Default]'
#	5. System Services
def SystemService():
	time.sleep(0.5)
	print '\t','_'*60,'\n\n5. System Services\t\t\t\t\t\t\t\t[Default]'
#	6. Registry
def Registry():
	time.sleep(0.5)
	print '\t','_'*60,'\n\n6. Registry\t\t\t\t\t\t\t\t\t[Default]'
#	7. File System
def FileSystem():
	time.sleep(0.5)
	print '\t','_'*60,'\n\n7. File System\t\t\t\t\t\t\t\t\t[Default]'
#	8. Wired Network (IEEE 802.3) Policies
def WiredNetwork():
	time.sleep(0.5)
	print '\t','_'*60,'\n\n8. Wired Network (IEEE 802.3) Policies\t\t\t\t\t\t[Default]'
#	9. Windows Firewall With Advanced Security
def WindowsFireWall():
	time.sleep(0.5)
	print '\t','_'*60,'\n\n9. Windows Firewall With Advanced Security'
	time.sleep(0.5)
	print '\n%s9.1 Domain Profile'%(' '*3)
	print '%s+ Firewall state'%(' '*7),'\t\t\t\t\t\t\t[%s]'%FirewallDomainProfile.Firewallstate()
	print '%s+ Inbound connections'%(' '*7),'\t\t\t\t\t\t\t[%s]'%FirewallDomainProfile.Inboundconnections()
	print '%s+ Outbound connections'%(' '*7),'\t\t\t\t\t\t\t[%s]'%FirewallDomainProfile.Outboundconnections()
	print '%s+ Settings: Display a notification'%(' '*7),'\t\t\t\t\t[%s]'%FirewallDomainProfile.Displayanotification()
	print '%s+ Settings: Apply local firewall rules'%(' '*7),'\t\t\t\t\t[%s]'%FirewallDomainProfile.Applylocalfirewallrules()
	print '%s+ Settings: Apply local connection security rules'%(' '*7),'\t\t\t[%s]'%FirewallDomainProfile.Applylocalconnectionsecurityrules()
	print '%s+ Logging: Name'%(' '*7),'\t\t\t\t\t\t\t\t[%s]'%FirewallDomainProfile.LoggingCustomizeName()
	print '%s+ Logging: Size limit (KB)'%(' '*7),'\t\t\t\t\t\t[%s]'%FirewallDomainProfile.LoggingCustomizeSize()
	print '%s+ Logging: Log dropped packets'%(' '*7),'\t\t\t\t\t\t[%s]'%FirewallDomainProfile.Logdroppedpackets()
	print '%s+ Logging: Log successful connections'%(' '*7),'\t\t\t\t\t[%s]'%FirewallDomainProfile.LogSuccessfulConnections()

	time.sleep(0.5)
	print '\n\n%s9.2 Private Profile'%(' '*3)
	print '%s+ Firewall state'%(' '*7),'\t\t\t\t\t\t\t[%s]'%FirewallPrivateProfile.Firewallstate()
	print '%s+ Inbound connections'%(' '*7),'\t\t\t\t\t\t\t[%s]'%FirewallPrivateProfile.Inboundconnections()
	print '%s+ Outbound connections'%(' '*7),'\t\t\t\t\t\t\t[%s]'%FirewallPrivateProfile.Outboundconnections()
	print '%s+ Settings: Display a notification'%(' '*7),'\t\t\t\t\t[%s]'%FirewallPrivateProfile.Displayanotification()
	print '%s+ Settings: Apply local firewall rules'%(' '*7),'\t\t\t\t\t[%s]'%FirewallPrivateProfile.Applylocalfirewallrules()
	print '%s+ Settings: Apply local connection security rules'%(' '*7),'\t\t\t[%s]'%FirewallPrivateProfile.Applylocalconnectionsecurityrules()
	print '%s+ Logging: Name'%(' '*7),'\t\t\t\t\t\t\t\t[%s]'%FirewallPrivateProfile.LoggingCustomizeName()
	print '%s+ Logging: Size limit (KB)'%(' '*7),'\t\t\t\t\t\t[%s]'%FirewallPrivateProfile.LoggingCustomizeSize()
	print '%s+ Logging: Log dropped packets'%(' '*7),'\t\t\t\t\t\t[%s]'%FirewallPrivateProfile.Logdroppedpackets()
	print '%s+ Logging: Log successful connections'%(' '*7),'\t\t\t\t\t[%s]'%FirewallPrivateProfile.LogSuccessfulConnections()

	time.sleep(0.5)
	print '\n\n%s9.3 Public Profile'%(' '*3)
	print '%s+ Firewall state'%(' '*7),'\t\t\t\t\t\t\t[%s]'%FirewallPublicProfile.Firewallstate()
	print '%s+ Inbound connections'%(' '*7),'\t\t\t\t\t\t\t[%s]'%FirewallPublicProfile.Inboundconnections()
	print '%s+ Outbound connections'%(' '*7),'\t\t\t\t\t\t\t[%s]'%FirewallPublicProfile.Outboundconnections()
	print '%s+ Settings: Display a notification'%(' '*7),'\t\t\t\t\t[%s]'%FirewallPublicProfile.Displayanotification()
	print '%s+ Settings: Apply local firewall rules'%(' '*7),'\t\t\t\t\t[%s]'%FirewallPublicProfile.Applylocalfirewallrules()
	print '%s+ Settings: Apply local connection security rules'%(' '*7),'\t\t\t[%s]'%FirewallPublicProfile.Applylocalconnectionsecurityrules()
	print '%s+ Logging: Name'%(' '*7),'\t\t\t\t\t\t\t\t[%s]'%FirewallPublicProfile.LoggingCustomizeName()
	print '%s+ Logging: Size limit (KB)'%(' '*7),'\t\t\t\t\t\t[%s]'%FirewallPublicProfile.LoggingCustomizeSize()
	print '%s+ Logging: Log dropped packets'%(' '*7),'\t\t\t\t\t\t[%s]'%FirewallPublicProfile.Logdroppedpackets()
	print '%s+ Logging: Log successful connections'%(' '*7),'\t\t\t\t\t[%s]'%FirewallPublicProfile.LogSuccessfulConnections()
#	10. Network List Manager Policies
def NetWorkListNanagerPolicies():
	time.sleep(0.5)
	print '\t','_'*60,'\n\n10. Network List Manager Policies\t\t\t\t\t\t[Default]'
#	11. Wireless Network (IEEE 802.11) Policies
def WirelessNetwork():
	time.sleep(0.5)
	print '\t','_'*60,'\n\n11. Wireless Network (IEEE 802.11) Policies\t\t\t\t\t[Default]'
#	12. Public Key Policies
def PuclicKeyPolicies():
	time.sleep(0.5)
	print '\t','_'*60,'\n\n12. Public Key Policies\t\t\t\t\t\t\t\t[Default]'
#	13. Software Restriction Policies
def SoftwareRestrictionPolicies():
	time.sleep(0.5)
	print '\t','_'*60,'\n\n13. Software Restriction Policies\t\t\t\t\t\t[Default]'
#	14. Network Access Protection NAP Client Configuration
def NAPClient():
	time.sleep(0.5)
	print '\t','_'*60,'\n\n14. Network Access Protection NAP Client Configuration\t\t\t\t[Default]'
#	15. Application Control Policies
def AppControlPolicies():
	time.sleep(0.5)
	print '\t','_'*60,'\n\n15. Application Control Policies\t\t\t\t\t\t[Default]'
#	16. IP Security Policies
def IPSecurity():
	time.sleep(0.5)
	print '\t','_'*60,'\n\n16. IP Security Policies\t\t\t\t\t\t\t[Default]'
#	17. Advanced Audit Policy Configuration
def AdAuPoConfig():
	time.sleep(0.5)
	print '\t','_'*60,'\n\n17. Advanced Audit Policy Configuration'
	time.sleep(0.5)
	print '\n%s17.1 Account Logon'%(' '*3)
	print '%s+ Audit Credential Validation'%(' '*7),'\t\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditCredentialValidation()
	
	time.sleep(0.5)
	print '\n%s17.2 Account Management'%(' '*3)
	print '%s+ Audit Application Group Management'%(' '*7),'\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditApplicationGroupManagement()
	print '%s+ Audit Computer Account Management'%(' '*7),'\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditComputerAccountManagement()
	print '%s+ Audit Other Account Management Events'%(' '*7),'\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditOtherAccountManagementEvents()
	print '%s+ Audit Security Group Management'%(' '*7),'\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditSecurityGroupManagement()
	print '%s+ Audit User Account Management'%(' '*7),'\t\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditUserAccountManagement()
	
	time.sleep(0.5)
	print '\n%s17.3 Detailed Tracking'%(' '*3)
	print '%s+ Audit Process Creation'%(' '*7),'\t\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditProcessCreation()
	
	time.sleep(0.5)
	print '\n%s17.4 DS Access'%(' '*3),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.5)
	print '\n%s17.5 Logon/Logoff'%(' '*3)
	print '%s+ Audit Account Lockout'%(' '*7),'\t\t\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditAccountLockout()
	print '%s+ Audit Logoff'%(' '*7),'\t\t\t\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditLogoff()
	print '%s+ Audit Logon'%(' '*7),'\t\t\t\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditLogon()
	print '%s+ Audit Other Logon/Logoff Events'%(' '*7),'\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditOtherLogonLogoffEvents()
	print '%s+ Audit Special Logon'%(' '*7),'\t\t\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditSpecialLogon()
	
	time.sleep(0.5)
	print '\n%s17.6 Object Access'%(' '*3),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.5)
	print '\n%s17.7 Policy Change'%(' '*3)
	print '%s+ Audit Audit Policy Change'%(' '*7),'\t\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditAuditPolicyChange()
	print '%s+ Audit Authentication Policy Change'%(' '*7),'\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditAuthenticationPolicyChange()
	
	time.sleep(0.5)
	print '\n%s17.8 Privilege Use'%(' '*3)
	print '%s+ Audit Sensitive Privilege Use'%(' '*7),'\t\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditSensitivePrivilegeUse()
	time.sleep(0.5)
	print '\n%s17.9 System'%(' '*3)
	print '%s+ Audit IPsec Driver'%(' '*7),'\t\t\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditIPsecDriver()
	print '%s+ Audit Other System Events'%(' '*7),'\t\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditOtherSystemEvents()
	print '%s+ Audit Security State Change'%(' '*7),'\t\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditSecurityStateChange()
	print '%s+ Audit Security System Extension'%(' '*7),'\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditSecuritySystemExtension()
	print '%s+ Audit System Integrity'%(' '*7),'\t\t\t\t\t\t[%s]'%AdvancedAuditPolicyConfiguration.AuditSystemIntegrity()
#	18. Administrative Templates (Computer)
def AdTemComputer():
	time.sleep(0.5)
	print '\t','_'*60,'\n\n18. Administrative Templates ( Computer )'
	time.sleep(0.5)
	print '\n%s18.1 Control Panel'%(' '*3),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.5)
	print '\n%s18.2 LAPS'%(' '*3)
	print '%s+ LAPS AdmPwd GPO Extension / CSE is installed'%(' '*7),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.AdmPwd()
	print '%s+ Do not allow password expiration time longer than required by policy'%(' '*7),'\t[%s]'%AdministrativeTemplatesComputer.PwdExpirationProtection()
	print '%s+ Enable Local Admin Password Management'%(' '*7),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.AdmPwdEnabled()
	print '%s+ Password Settings: Password Complexity'%(' '*7),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.PasswordComplexity()
	print '%s+ Password Settings: Password Length'%(' '*7),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.PasswordLength()
	print '%s+ Password Settings: Password Age (Days)'%(' '*7),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.PasswordAgeDays()
	
	time.sleep(0.5)
	print '\n%s18.3 MSS ( Legacy )'%(' '*3)
	print '%s+ Enable Automatic Logon (not recommended)'%(' '*7),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.AutoAdminLogon()
	print '%s+ IPv6 source routing protection level'%(' '*7),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.DisableIP6SourceRouting()
	print '%s+ IPv4 source routing protection level'%(' '*7),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.DisableIPSourceRouting()
	print '%s+ Prevent the dial-up password from being saved'%(' '*7),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.Disablesavepassword()
	print '%s+ Allow ICMP redirects to override OSPF generated routes'%(' '*7),'\t\t[%s]'%AdministrativeTemplatesComputer.EnableICMPRedirect()
	print '%s+ How often keep-alive packets are sent in milliseconds'%(' '*7),'\t\t\t[%s]'%AdministrativeTemplatesComputer.KeepAliveTime()
	print '%s+ Allow PC to ignore NetBIOS name release requests except from WINS'%(' '*7),'\t[%s]'%AdministrativeTemplatesComputer.Nonamereleaseondemand()
	print '%s+ Allow IRDP to detect and configure Default Gateway addresses'%(' '*7),'\t\t[%s]'%AdministrativeTemplatesComputer.PerformRouterDiscovery()
	print '%s+ Enable Safe DLL search mode'%(' '*7),'\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.SafeDllSearchMode()
	print '%s+ The time in seconds before the screen saver grace period expires'%(' '*7),'\t[%s]'%AdministrativeTemplatesComputer.ScreenSaverGracePeriod()
	print '%s+ How many times unacknowledged data is retransmitted'%(' '*7),'\t\t\t[%s]'%AdministrativeTemplatesComputer.Tcpmaxdataretransmissions6()
	print '%s+ How many times unacknowledged data is retransmitted'%(' '*7),'\t\t\t[%s]'%AdministrativeTemplatesComputer.Tcpmaxdataretransmissions()
	print '%s+ Percentage threshold for the SeEvLog of sys will generate a warning'%(' '*7),'\t[%s]'%AdministrativeTemplatesComputer.WARNINGLevel()
	
	time.sleep(0.5)
	print '\n%s18.4 Network'%(' '*3)
	time.sleep(0.25)
	print '%s+ Background Intelligent Transfer Service (BITS)'%(' '*7),'\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ BranchCache'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ DirectAccess Client Experience Settings'%(' '*7),'\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ DNS Client'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Hotspot Authentication'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Lanman Server'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Lanman Workstation'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Link-Layer Topology Discovery'%(' '*7)
	print '%s* Turn on Mapper I/O (LLTDIO) driver'%(' '*11),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.TurnonMapperIO()
	print '%s* Turn on Responder (RSPNDR) driver'%(' '*11),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.TurnonResponder()
	time.sleep(0.25)
	print '%s+ Microsoft Peer-to-Peer Networking Services'%(' '*7)
	print '%s* Peer Name Resolution Protocol'%(' '*11),'\t\t\t\t\t[Default]'
	print '%s* Turn off Microsoft Peer-to-Peer Networking Services'%(' '*11),'\t\t[%s]'%AdministrativeTemplatesComputer.Peernet()
	time.sleep(0.25)
	print '%s+ Network Connections'%(' '*7)
	print '%s* Windows Firewall'%(' '*11),'\t\t\t\t\t\t\t[Default]'
	print '%s* Prohibit instal and config of Network Bridge on your DNS domain'%(' '*11),'\t[%s]'%AdministrativeTemplatesComputer.NCAllowNetBridgeNLA()
	print "%s* Require domain users to elevate when setting a network's location"%(' '*11),'\t[%s]'%AdministrativeTemplatesComputer.NCStdDomainUserSetLocation()
	time.sleep(0.25)
	print '%s+ Network Connectivity Status Indicator'%(' '*7),'\t\t\t\t\t[Default]'
	print '%s+ Network Isolation'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	print '%s+ Network Provider'%(' '*7)
	print '%s* Hardened UNC Paths'%(' '*11),'\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.HardenedPaths()
	time.sleep(0.25)
	print '%s+ Offline Files'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	print '%s+ QoS Packet Scheduler'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	print '%s+ SNMP'%(' '*7),'\t\t\t\t\t\t\t\t\t[Default]'
	print '%s+ SSL Configuration Settings'%(' '*7),'\t\t\t\t\t\t[Default]'
	print '%s+ TCPIP Settings'%(' '*7)
	time.sleep(0.25)
	print '%s* IPv6 Transition Technologies'%(' '*11),'\t\t\t\t\t[Default]'
	print '%s* Parameters'%(' '*11)
	# time.sleep(0.25)
	print '%s> Disable IPv6'%(' '*15),'\t\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.DisabledComponents()

	print '%s+ Windows Connect Now'%(' '*7)
	time.sleep(0.25)
	print '%s* Configuration of wireless settings using Windows Connect Now'%(' '*11),'\t[%s]'%AdministrativeTemplatesComputer.Registrars()
	print '%s* Prohibit access of the Windows Connect Now wizards'%(' '*11),'\t\t[%s]'%AdministrativeTemplatesComputer.DisableWcnUi()

	time.sleep(0.5)
	print '\n%s18.5 Printers'%(' '*3),'\t\t\t\t\t\t\t\t[Default]'
	print '\n%s18.6 SCM: Pass the Hash Mitigations'%(' '*3)
	time.sleep(0.25)
	print '%s+ Apply UAC restrictions to local accounts on network logons'%(' '*7),'\t\t[%s]'%AdministrativeTemplatesComputer.LocalAccountTokenFilterPolicy()
	print '%s+ WDigest Authentication'%(' '*7),'\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.UseLogonCredential()

	time.sleep(0.5)
	print '\n%s18.7 Start Menu and Taskbar'%(' '*3),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.5)
	print '\n%s18.8 System'%(' '*3) 
	print '%s+ Access-Denied Assistance'%(' '*7),'\t\t\t\t\t\t[Default]'
	print '%s+ Audit Process Creation'%(' '*7) 
	time.sleep(0.25)
	print '%s* Include command line in process creation events'%(' '*11),'\t\t\t[%s]'%AdministrativeTemplatesComputer.ProcessCreationIncludeCmdLineEnabled()
	print '%s+ Credentials Delegation'%(' '*7),'\t\t\t\t\t\t[Default]'
	print '%s+ Device Guard'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	print '%s+ Device Installation'%(' '*7)
	print '%s* Device Installation Restrictions'%(' '*11)
	print '%s> Prevent installation of devices using drivers that match \n%sthese device setup classes'%(' '*15,' '*17),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.DenyDeviceClasses()
	print '%s> Prevent installation of devices using drivers \n%sfor these device setup'%(' '*15,' '*17),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.DenyDeviceClasses1()
	print '%s> Also apply to matching devices that are already installed'%(' '*15),'\t[%s]'%AdministrativeTemplatesComputer.DenyDeviceClassesRetroactive()
	print '%s* Allow remote access to the Plug and Play interface'%(' '*11),'\t\t[%s]'%AdministrativeTemplatesComputer.AllowRemoteRPC()
	time.sleep(0.25)
	print '%s+ Device Redirection'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Disk NV Cache'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Distributed COM'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Driver Installation'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Early Launch Antimalware'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Enhanced Storage Access'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ File Classification Infrastructure'%(' '*7),'\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ File Share Shadow Copy Agent'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ File Share Shadow Copy Provider'%(' '*7),'\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Filesystem'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Folder Redirection'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Group Policy'%(' '*7)
	time.sleep(0.25)
	print '%s* Logging and tracing'%(' '*11),'\t\t\t\t\t\t[Default]'
	print '%s* Configure registry policy processing: Do not apply \n\t\t\t\tduring periodic background processing'%(' '*11),'\t\t[%s]'%AdministrativeTemplatesComputer.NoBackgroundPolicy()
	print '%s* Configure registry policy processing: Process even if the Group  \n%sPolicy objects have not changed'%(' '*11,' '*13),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.NoGPOListChanges()
	print '%s* Turn off background refresh of Group Policy'%(' '*11),'\t\t\t[%s]'%AdministrativeTemplatesComputer.DisableBkGndGroupPolicy()
	print '\n%s+ Internet Communication Management'%(' '*7)
	time.sleep(0.25)
	print '%s* Internet Communication settings'%(' '*11)
	time.sleep(0.25)
	print '%s> Turn off downloading of print drivers over HTTP'%(' '*15),'\t\t[%s]'%AdministrativeTemplatesComputer.DisableWebPnPDownload()
	print '%s> Turn off handwriting personalization data sharing'%(' '*15),'\t\t[%s]'%AdministrativeTemplatesComputer.PreventHandwritingDataSharing()
	print '%s> Turn off handwriting recognition error reporting'%(' '*15),'\t\t[%s]'%AdministrativeTemplatesComputer.PreventHandwritingErrorReports()
	print '%s> Turn off Internet Connection Wizard if URL connection \n%sis referring to Microsoft.com'%(' '*15,' '*17),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.ExitOnMSICW()
	print '%s> Turn off Internet download for Web publishing \n%sand online ordering wizards'%(' '*15,' '*17),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.NoWebServices()
	print '%s> Turn off Internet File Association service'%(' '*15),'\t\t\t[%s]'%AdministrativeTemplatesComputer.NoInternetOpenWith()
	print '%s> Turn off printing over HTTP'%(' '*15),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.DisableHTTPPrinting()
	print '%s> Turn off Registration if URL connection is referring \n%sto Microsoft.com'%(' '*15,' '*17),'\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.NoRegistration()
	print '%s> Turn off Search Companion content file updates'%(' '*15),'\t\t[%s]'%AdministrativeTemplatesComputer.DisableContentFileUpdates()
	print '%s> Turn off the "Order Prints" picture task'%(' '*15),'\t\t\t[%s]'%AdministrativeTemplatesComputer.NoOnlinePrintsWizard()
	print '%s> Turn off the "Publish to Web" task for files and folders'%(' '*15),'\t[%s]'%AdministrativeTemplatesComputer.NoPublishingWizard()
	print '%s> Turn off the Windows Messenger Customer \n%sExperience Improvement Program'%(' '*15,' '*17),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.CEIP()
	print '%s> Turn off Windows Customer Experience Improvement Program'%(' '*15),'\t[%s]'%AdministrativeTemplatesComputer.CEIPEnable()
	print '%s> Turn off Windows Error Reporting'%(' '*15),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.WindowsErrorReporting()

	time.sleep(0.25)
	print '%s+ iSCSI'%(' '*7),'\t\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ KDC'%(' '*7),'\t\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Kerberos'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Locale Services'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Logon'%(' '*7)
	time.sleep(0.25)
	print '%s* Always use classic logon'%(' '*11),'\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.LogonType()
	time.sleep(0.25)
	print '%s+ Mitigation Options'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Net Logon'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Performance Control Panel'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Power Management'%(' '*7)
	time.sleep(0.25)
	print '%s* Button Settings'%(' '*11),'\t\t\t\t\t\t\t[Default]'
	print '%s* Hard Disk Settings'%(' '*11),'\t\t\t\t\t\t[Default]'
	print '%s* Notification Settings'%(' '*11),'\t\t\t\t\t\t[Default]'
	print '%s* Sleep Settings'%(' '*11)
	time.sleep(0.25)
	print '%s> Allow standby states (S1-S3) when sleeping (on battery)'%(' '*15),'\t[%s]'%AdministrativeTemplatesComputer.DCSettingIndex()
	print '%s> Allow standby states (S1-S3) when sleeping (plugged in)'%(' '*15),'\t[%s]'%AdministrativeTemplatesComputer.ACSettingIndex()
	print '%s> Require a password when a computer wakes (on battery)'%(' '*15),'\t\t[%s]'%AdministrativeTemplatesComputer.DCSettingIndex1()
	print '%s> Require a password when a computer wakes (plugged in)'%(' '*15),'\t\t[%s]'%AdministrativeTemplatesComputer.ACSettingIndex1()
	time.sleep(0.25)
	print '%s+ Recovery'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Remote Assistance'%(' '*7)
	print '%s* Configure Offer Remote Assistance'%(' '*11),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.fAllowUnsolicited()
	print '%s* Configure Solicited Remote Assistance'%(' '*11),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.fAllowToGetHelp()
	print '%s+ Remote Procedure Call'%(' '*7)
	print '%s* Enable RPC Endpoint Mapper Client Authentication'%(' '*11),'\t\t\t[%s]'%AdministrativeTemplatesComputer.EnableAuthEpResolution()
	print '%s* Restrict Unauthenticated RPC clients'%(' '*11),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.RestrictRemoteClients()

	print '%s+ Removable Storage Access'%(' '*7),'\t\t\t\t\t\t[Default]'
	print '%s+ Scripts'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	print '%s+ Server Manager'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	print '%s+ Shutdown'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	print '%s+ Shutdown Options'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	print '%s+ System Restore'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	print '%s+ Troubleshooting and Diagnostics'%(' '*7)
	time.sleep(0.25)
	print '%s* Turn on MSDT interactive communication with support provider'%(' '*11),'\t[Default]'
	time.sleep(0.25)
	print '%s* Corrupted File Recovery'%(' '*11),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s* Disk Diagnostic'%(' '*11),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s* Fault Tolerant Heap'%(' '*11),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s* Microsoft Support Diagnostic Tool'%(' '*11)
	time.sleep(0.25)
	print '%s> Allow standby states (S1-S3) when sleeping (on battery)'%(' '*15),'\t[%s]'%AdministrativeTemplatesComputer.DisableQueryRemoteServer()
	time.sleep(0.25)
	print '%s* MSI Corrupted File Recovery'%(' '*11),'\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s* Scheduled Maintenance'%(' '*11),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s* Scripted Diagnostics'%(' '*11),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	time.sleep(0.25)
	print '%s* Windows Boot Performance Diagnostics'%(' '*11),'\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s* Windows Memory Leak Diagnosis'%(' '*11),'\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s* Windows Performance PerfTrack'%(' '*11)
	print '%s> Enable/Disable PerfTrack'%(' '*15),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.ScenarioExecutionEnabled()
	print '%s+ Trusted Platform Module Services'%(' '*7),'\t\t\t\t\t[Default]'
	print '%s+ User Profiles'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	print '%s+ Windows File Protection'%(' '*7),'\t\t\t\t\t\t[Default]'
	print '%s+ Windows HotStart'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	print '%s+ Windows Time Service'%(' '*7)
	print '%s* Time Providers'%(' '*11)
	print '%s> Enable Windows NTP Client'%(' '*15),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.NtpClient()
	print '%s> Enable Windows NTP Server'%(' '*15),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.NtpServer()



	time.sleep(0.5)
	print '\n%s18.9 Windows Components'%(' '*3) 
	time.sleep(0.25)
	print '%s+ Active Directory Federation Services'%(' '*7),'\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ ActiveX Installer Service'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Add features to Windows 8 / 8.1 / 10'%(' '*7),'\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ App Package Deployment'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ App Privacy'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ App runtime'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Application Compatibility'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ AutoPlay Policies'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s* Disallow Autoplay for non-volume devices'%(' '*11),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.NoAutoplayfornonVolume()
	print '%s* Set the default behavior for AutoRun'%(' '*11),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.NoAutorun()
	print '%s* Turn off Autoplay'%(' '*11),'\t\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.NoDriveTypeAutoRun()


	time.sleep(0.25)
	print '%s+ Backup'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ Biometrics'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s+ BitLocker Drive Encryption'%(' '*7)
	time.sleep(0.25)
	print '%s* Fixed Data Drives'%(' '*11)
	time.sleep(0.25)
	print '%s> Allow access to BitLocker-protected \n%sfixed data drives from earlier versions of Windows'%(' '*15,' '*17),'\t\t[%s]'%AdministrativeTemplatesComputer.FDVDiscoveryVolumeType()
	print '%s> Choose how BitLocker-protected fixed drives can be recovered'%(' '*15),'\t[%s]'%AdministrativeTemplatesComputer.FDVRecovery()
	print '%s> Allow data recovery agent'%(' '*15),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.FDVManageDRA()
	print '%s> Recovery Password'%(' '*15),'\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.FDVRecoveryPassword()
	print '%s> Recovery Key'%(' '*15),'\t\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.FDVRecoveryKey()
	print '%s> Omit recovery options from the BitLocker setup wizard'%(' '*15),'\t\t[%s]'%AdministrativeTemplatesComputer.FDVHideRecoveryPage()
	print '%s> Save BitLocker recovery information to AD DS \n%sfor fixed data drives'%(' '*15,' '*17),'\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.FDVActiveDirectoryBackup()
	print '%s> Configure storage of BitLocker recovery information to AD DS'%(' '*15),'\t[%s]'%AdministrativeTemplatesComputer.FDVActiveDirectoryInfoToStore()
	print '%s> Do not enable BitLocker until recovery information \n%sis stored to AD DS for fixed data drives'%(' '*15,' '*17),'\t\t\t[%s]'%AdministrativeTemplatesComputer.FDVRequireActiveDirectoryBackup()
	print '%s> Configure use of passwords for fixed data drives'%(' '*15),'\t\t[%s]'%AdministrativeTemplatesComputer.FDVPassphrase()
	print '%s> Configure use of smart cards on fixed data drives'%(' '*15),'\t\t[%s]'%AdministrativeTemplatesComputer.FDVAllowUserCert()
	print '%s> Require use of smart cards on fixed data drives'%(' '*15),'\t\t[%s]'%AdministrativeTemplatesComputer.FDVEnforceUserCert()
	time.sleep(0.25)
	print '%s* Operating System Drives'%(' '*11)
	time.sleep(0.25)
	print '%s> Allow enhanced PINs for startup'%(' '*15),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.UseEnhancedPin()
	print '%s> Choose how BitLocker-protected operating system \n%sdrives can be recovered'%(' '*15,' '*17),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.OSRecovery()
	print '%s> Allow data recovery agent'%(' '*15),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.OSManageDRA()
	print '%s> Recovery Password'%(' '*15),'\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.OSRecoveryPassword()
	print '%s> Recovery Key'%(' '*15),'\t\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.OSRecoveryKey()
	print '%s> Omit recovery options from the BitLocker setup wizard'%(' '*15),'\t\t[%s]'%AdministrativeTemplatesComputer.OSHideRecoveryPage()
	print '%s> Save BitLocker recovery information to AD DS \n%sfor operating system drives'%(' '*15,' '*17),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.OSActiveDirectoryBackup()
	print '%s> Configure storage of BitLocker recovery information to AD DS'%(' '*15),'\t[%s]'%AdministrativeTemplatesComputer.OSActiveDirectoryInfoToStore()
	print '%s> Do not enable BitLocker until recovery information is stored \n%sto AD DS for operating system drives'%(' '*15,' '*17),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.OSRequireActiveDirectoryBackup()
	print '%s> Configure minimum PIN length for startup'%(' '*15),'\t\t\t[%s]'%AdministrativeTemplatesComputer.MinimumPIN()
	print '%s> Require additional authentication at startup'%(' '*15),'\t\t\t[%s]'%AdministrativeTemplatesComputer.UseAdvancedStartup()
	print '%s> Allow BitLocker without a compatible TPM'%(' '*15),'\t\t\t[%s]'%AdministrativeTemplatesComputer.EnableBDEWithNoTPM()
	print '%s> Configure TPM startup'%(' '*15),'\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.UseTPM()
	print '%s> Configure TPM startup PIN'%(' '*15),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.UseTPMPIN()
	print '%s> Configure TPM startup key'%(' '*15),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.UseTPMKey()
	print '%s> Configure TPM startup key and PIN'%(' '*15),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.UseTPMKeyPIN()
	time.sleep(0.25)
	print '%s* Removable Data Drives'%(' '*11)
	time.sleep(0.25)
	print '%s> Allow access to BitLocker-protected removable data \n%sdrives from earlier versions of Windows'%(' '*15,' '*17),'\t\t\t[%s]'%AdministrativeTemplatesComputer.RDVDiscoveryVolumeType()
	print '%s> Choose how BitLocker-protected removable \n%sdrives can be recovered'%(' '*15,' '*17),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.RDVRecovery()
	print '%s> Allow data recovery agent'%(' '*15),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.RDVManageDRA()
	print '%s> Recovery Password'%(' '*15),'\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.RDVRecoveryPassword()
	print '%s> Recovery Key'%(' '*15),'\t\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.RDVRecoveryKey()
	print '%s> Omit recovery options from the BitLocker setup wizard'%(' '*15),'\t\t[%s]'%AdministrativeTemplatesComputer.RDVHideRecoveryPage()
	print '%s> Save BitLocker recovery information to AD DS \n%sfor removable data drives'%(' '*15,' '*17),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.RDVActiveDirectoryBackup()
	print '%s> Configure storage of BitLocker recovery information to AD DS'%(' '*15),'\t[%s]'%AdministrativeTemplatesComputer.RDVActiveDirectoryInfoToStore()
	print '%s> Do not enable BitLocker until recovery information is stored \n%sto AD DS for removable data drives'%(' '*15,' '*17),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.RDVRequireActiveDirectoryBackup()
	print '%s> Configure use of passwords for removable data drives'%(' '*15),'\t\t[%s]'%AdministrativeTemplatesComputer.RDVPassphrase()
	print '%s> Configure use of smart cards on removable data drives'%(' '*15),'\t\t[%s]'%AdministrativeTemplatesComputer.RDVAllowUserCert()
	print '%s> Require use of smart cards on removable data drives'%(' '*15),'\t\t[%s]'%AdministrativeTemplatesComputer.RDVEnforceUserCert()
	print '%s> Deny write access to removable drives not protected \n%sby BitLocker'%(' '*15,' '*17),'\t\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.RDVDenyWriteAccess()
	print '%s> Do not allow write access to devices \n%sconfigured in another organization'%(' '*15,' '*17),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.RDVDenyCrossOrg()
	time.sleep(0.25)
	print '\n%s* Choose drive encryption method and cipher strength'%(' '*11),'\t\t[%s]'%AdministrativeTemplatesComputer.EncryptionMethod()
	time.sleep(0.5)
	print '\n%s+ Cloud Content'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.5)
	print '%s+ Credential User Interface'%(' '*7)
	time.sleep(0.25)
	print '%s* Do not display the password reveal button'%(' '*11),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.DisablePasswordReveal()
	print '%s* Enumerate administrator accounts on elevation'%(' '*11),'\t\t\t[%s]'%AdministrativeTemplatesComputer.EnumerateAdministrators()
	time.sleep(0.5)
	print '\n%s+ Data Collection and Preview Builds'%(' '*7),'\t\t\t\t\t[Default]'
	print '\n%s+ Delivery Optimization'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	print '\n%s+ Desktop Gadgets'%(' '*7)
	time.sleep(0.25)
	print '%s* Turn off desktop gadgets'%(' '*11),'\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.TurnOffSidebar()
	print '%s* Turn Off user-installed desktop gadgets'%(' '*11),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.TurnOffUserInstalledGadgets()
	time.sleep(0.25)
	print '\n%s+ Desktop Window Manager'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Device and Driver Compatibility'%(' '*7),'\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Device Registration (formerly Workplace Join)'%(' '*7),'\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Digital Locker'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Edge UI'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ EMET'%(' '*7)
	time.sleep(0.25)
	print "%s* EMET 5.5' or higher is installed"%(' '*11),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.EMETInstall()
	print '%s* Default Action and Mitigation Settings'%(' '*11),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.SysSettings()
	print '%s* Default Protections for Internet Explorer'%(' '*11),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.IE()
	print '%s* Default Protections for Popular Software'%(' '*11),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.Defaults()
	print '%s* Default Protections for Recommended Software'%(' '*11),'\t\t\t[%s]'%AdministrativeTemplatesComputer.Defaults1()
	print '%s* System ASLR'%(' '*11),'\t\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.ASLR()
	print '%s* System DEP'%(' '*11),'\t\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.DEP()
	print '%s* System SEHOP'%(' '*11),'\t\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.SEHOP()
	time.sleep(0.25)
	print '\n%s+ Event Forwarding'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	print '\n%s+ Event Log Service'%(' '*7)
	time.sleep(0.25)
	print '%s* Application'%(' '*11)
	time.sleep(0.25)
	print '%s> Control Event Log behavior when the log file \n%sreaches its maximum size'%(' '*15,' '*17),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.Retention()
	print '%s> Specify the maximum log file size (KB)'%(' '*15),'\t\t\t[%s]'%AdministrativeTemplatesComputer.MaxSize()
	time.sleep(0.25)
	print '%s* Security'%(' '*11)
	print '%s> Control Event Log behavior when the log file \n%sreaches its maximum size'%(' '*15,' '*17),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.Retention1()
	print '%s> Specify the maximum log file size (KB)'%(' '*15),'\t\t\t[%s]'%AdministrativeTemplatesComputer.MaxSize1()
	time.sleep(0.25)
	print '%s* Security'%(' '*11)
	print '%s> Control Event Log behavior when the log file \n%sreaches its maximum size'%(' '*15,' '*17),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.Retention2()
	print '%s> Specify the maximum log file size (KB)'%(' '*15),'\t\t\t[%s]'%AdministrativeTemplatesComputer.MaxSize2()
	time.sleep(0.25)
	print '%s* System'%(' '*11)
	print '%s> Control Event Log behavior when the log file \n%sreaches its maximum size'%(' '*15,' '*17),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.Retention3()
	print '%s> Specify the maximum log file size (KB)'%(' '*15),'\t\t\t[%s]'%AdministrativeTemplatesComputer.MaxSize3()
	time.sleep(0.25)
	print '\n%s+ Event Logging'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	print '\n%s+ Event Viewer'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	print '\n%s+ Family Safety'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	print '\n%s+ File Explorer'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	print '%s* Previous Versions'%(' '*11),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s* Turn off Data Execution Prevention for Explorer'%(' '*11),'\t\t\t[%s]'%AdministrativeTemplatesComputer.NoDataExecutionPrevention()
	print '%s* Turn off heap termination on corruption'%(' '*11),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.NoHeapTerminationOnCorruption()
	print '%s* Turn off shell protocol protected mode'%(' '*11),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.PreXPSP2ShellProtocolBehavior()
	time.sleep(0.25)
	print '\n%s+ File History'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Game Explorer'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ HomeGroup'%(' '*7)
	time.sleep(0.25)
	print '%s* Prevent the computer from joining a homegroup'%(' '*11),'\t\t\t[%s]'%AdministrativeTemplatesComputer.DisableHomeGroup()
	time.sleep(0.25)
	print '\n%s+ Import Video'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Internet Explorer'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Internet Information Services'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Location and Sensors'%(' '*7)
	time.sleep(0.25)
	print '%s* Turn off location'%(' '*11),'\t\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.DisableLocation()
	time.sleep(0.25)
	print '\n%s+ Maintenance Scheduler'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Maps'%(' '*7),'\t\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Microsoft Edge'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Microsoft Passport for Work'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ NetMeeting'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Network Access Protection'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Network Projector'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ OneDrive'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Online Assistance'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Password Synchronization'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Portable Operating System'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Presentation Settings'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Remote Desktop Services (formerly Terminal Services)'%(' '*7),'\t\t\t[Default]'
	time.sleep(0.25)
	print '%s* RD Licensing'%(' '*11),'\t\t\t\t\t\t\t[Default]'
	print '%s* Remote Desktop Connection Client'%(' '*11)
	time.sleep(0.25)
	print '%s> RemoteFX USB Device Redirection'%(' '*15),'\t\t\t\t[Default]'
	print '%s> Do not allow passwords to be saved'%(' '*15),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.DisablePasswordSaving()
	print '%s* Remote Desktop Session Host'%(' '*11)
	time.sleep(0.25)
	print '%s> Application Compatibility'%(' '*15),'\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s> Connections'%(' '*15)
	time.sleep(0.25)
	print '%s~ Allow users to connect remotely by using Remote \n%sDesktop Services'%(' '*19,' '*21),'\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.fDenyTSConnections()
	print '%s> Device and Resource Redirection'%(' '*15)
	time.sleep(0.25)
	print '%s~ Do not allow COM port redirection'%(' '*19),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.fDisableCcm()
	print '%s~ Do not allow drive redirection'%(' '*19),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.fDisableCdm()
	print '%s~ Do not allow LPT port redirection'%(' '*19),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.fDisableLPT()
	print '%s~ Do not allow supported Plug and Play device redirection'%(' '*19),'\t[%s]'%AdministrativeTemplatesComputer.fDisablePNPRedir()
	time.sleep(0.25)
	print '%s> Licensing'%(' '*15),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s> Printer Redirection'%(' '*15),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s> Profiles'%(' '*15),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s> RD Connection Broker'%(' '*15),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s> Remote Session Environment'%(' '*15),'\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s> Security'%(' '*15)
	time.sleep(0.25)
	print '%s~ Always prompt for password upon connection'%(' '*19),'\t\t[%s]'%AdministrativeTemplatesComputer.fPromptForPassword()
	print '%s~ Require secure RPC communication'%(' '*19),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.fEncryptRPCTraffic()
	print '%s~ Set client connection encryption level'%(' '*19),'\t\t\t[%s]'%AdministrativeTemplatesComputer.MinEncryptionLevel()
	time.sleep(0.25)
	print '%s> Session Time Limits'%(' '*15)
	time.sleep(0.25)
	print '%s~ Set time limit for active but idle \n%sRemote Desktop Services sessions'%(' '*19,' '*21),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.MaxIdleTime()
	print '%s~ Set time limit for disconnected sessions'%(' '*19),'\t\t\t[%s]'%AdministrativeTemplatesComputer.MaxDisconnectionTime()
	time.sleep(0.25)
	print '%s> Temporary folders'%(' '*15)
	time.sleep(0.25)
	print '%s~ Do not delete temp folders upon exit'%(' '*19),'\t\t\t[%s]'%AdministrativeTemplatesComputer.DeleteTempDirsOnExit()
	print '%s~ Do not use temporary folders per session'%(' '*19),'\t\t\t[%s]'%AdministrativeTemplatesComputer.PerSessionTempDir()
	time.sleep(0.25)
	print '\n%s+ RSS Feeds'%(' '*7)
	time.sleep(0.25)
	print '%s* Prevent downloading of enclosures'%(' '*11),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.DisableEnclosureDownload()
	time.sleep(0.25)
	print '\n%s+ Search'%(' '*7)
	time.sleep(0.25)
	print '%s* OCR'%(' '*11),'\t\t\t\t\t\t\t\t[Default]'
	print '%s* Allow indexing of encrypted files'%(' '*11),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.AllowIndexingEncryptedStoresOrItems()
	time.sleep(0.25)
	print '\n%s+ Security Center'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Server for NIS'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Shutdown Options'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ SkyDrive'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Smart Card'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Software Protection Platform'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Sound Recorder'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Store'%(' '*7),'\t\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Sync your settings'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Tablet PC'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Task Scheduler'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Text Input'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Windows Calendar'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Windows Color System'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Windows Customer Experience Improvement Program'%(' '*7),'\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Windows Defender'%(' '*7)
	time.sleep(0.25)
	print '%s* Client Interface'%(' '*11),'\t\t\t\t\t\t\t[Default]'
	print '%s* Exclusions'%(' '*11),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '%s* MAPS'%(' '*11)
	time.sleep(0.25)
	print '%s> Join Microsoft MAPS'%(' '*15),'\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.SpynetReporting()
	time.sleep(0.25)
	print '\n%s+ Windows Error Reporting'%(' '*7)
	time.sleep(0.25)
	print '%s* Advanced Error Reporting Settings'%(' '*11),'\t\t\t\t\t[Default]'
	print '%s* Consent'%(' '*11)
	time.sleep(0.25)
	print '%s> Configure Default consent'%(' '*15),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.DefaultConsent()
	time.sleep(0.25)
	print '\n%s+ Windows Game Recording and Broadcasting'%(' '*7),'\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Windows Installer'%(' '*7)
	time.sleep(0.25)
	print '%s* Allow user control over installs'%(' '*11),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.EnableUserControl()
	print '%s* Always install with elevated privileges'%(' '*11),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.AlwaysInstallElevated()
	print '%s* Prevent Internet Explorer security prompt for Windows \n%sInstaller scripts'%(' '*11,' '*13),'\t\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.SafeForScripting()
	time.sleep(0.25)
	print '\n%s+ Windows Logon Options'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Windows Mail'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Windows Media Center'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Windows Media Digital Rights Management'%(' '*7),'\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Windows Media Player'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Windows Meeting Space'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Windows Messenger'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Windows Mobility Center'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Windows Movie Maker'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Windows PowerShell'%(' '*7)
	time.sleep(0.25)
	print '%s* Turn on PowerShell Script Block Logging'%(' '*11),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.EnableScriptBlockLogging()
	print '%s* Turn on PowerShell Transcription'%(' '*11),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.EnableTranscripting()
	time.sleep(0.25)
	print '\n%s+ Windows Reliability Analysis'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Windows Remote Management (WinRM)'%(' '*7)
	time.sleep(0.25)
	print '%s* WinRM Client'%(' '*11)
	time.sleep(0.25)
	print '%s> Allow Basic authentication'%(' '*15),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.AllowBasic()
	print '%s> Allow unencrypted traffic'%(' '*15),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.AllowUnencryptedTraffic()
	print '%s> Disallow Digest authentication'%(' '*15),'\t\t\t\t[%s]'%AdministrativeTemplatesComputer.AllowDigest()
	time.sleep(0.25)
	print '%s* WinRM Service'%(' '*11)
	time.sleep(0.25)
	print '%s> Allow Basic authentication'%(' '*15),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.AllowBasicService()
	print '%s> Allow unencrypted traffic'%(' '*15),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.AllowUnencryptedTrafficService()
	print '%s> Disallow WinRM from storing RunAs credentials'%(' '*15),'\t\t\t[%s]'%AdministrativeTemplatesComputer.DisableRunAs()
	time.sleep(0.25)
	print '\n%s+ Windows SideShow'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Windows System Resource Manager'%(' '*7),'\t\t\t\t\t[Default]'
	time.sleep(0.25)
	print '\n%s+ Windows Update'%(' '*7)
	time.sleep(0.25)
	print '%s* Configure Automatic Updates'%(' '*11),'\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.NoAutoUpdate()
	print '%s* Scheduled install day'%(' '*11),'\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.ScheduledInstallDay()
	print "%s* Do not adjust default option to 'Install Updates and \n%sShut Down' in Shut Down Windows dialog box"%(' '*11,' '*13),'\t\t\t[%s]'%AdministrativeTemplatesComputer.NoAUAsDefaultShutdownOption()
	print "%s* Do not display 'Install Updates and Shut Down' option in Shut Down \n%sWindows dialog box"%(' '*11,' '*13),'\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.NoAUShutdownOption()
	print '%s* No auto-restart with logged on users for scheduled automatic \n%supdates installations'%(' '*11,' '*13),'\t\t\t\t\t\t[%s]'%AdministrativeTemplatesComputer.NoAutoRebootWithLoggedOnUsers()
	print '%s* Reschedule Automatic Updates scheduled installations'%(' '*11),'\t\t[%s]'%AdministrativeTemplatesComputer.RescheduleWaitTime()
#	19. Administrative Templates (User)
def AdTemUser():
	time.sleep(0.5)
	print '\t','_'*60,'\n\n19. Administrative Templates (User)'
	time.sleep(0.5)
	print '\n%s19.1 Control Panel'%(' '*3)
	print '%s+ Add or Remove Programs'%(' '*7),'\t\t\t\t\t\t[Default]'
	print '%s+ Display'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	print '%s+ Personalization'%(' '*7)
	print '%s* Enable screen saver'%(' '*11),'\t\t\t\t\t\t[%s]'%AdministrativeTemplatesUser.ScreenSaveActive()
	print '%s* Force specific screen saver: Screen saver executable name'%(' '*11),'\t\t[%s]'%AdministrativeTemplatesUser.SCRNSAVE()
	print '%s* Password protect the screen saver'%(' '*11),'\t\t\t\t\t[%s]'%AdministrativeTemplatesUser.ScreenSaverIsSecure()
	print '%s* Screen saver timeout'%(' '*11),'\t\t\t\t\t\t[%s]'%AdministrativeTemplatesUser.ScreenSaveTimeOut()
	
	time.sleep(0.5)
	print '\n%s19.2 Desktop'%(' '*3),'\t\t\t\t\t\t\t\t[Default]'
	
	time.sleep(0.5)
	print '\n%s19.3 Network'%(' '*3),'\t\t\t\t\t\t\t\t[Default]'
	
	time.sleep(0.5)
	print '\n%s19.4 Shared Folders'%(' '*3),'\t\t\t\t\t\t\t\t[Default]'
	
	time.sleep(0.5)
	print '\n%s19.5 Start Menu and Taskbar'%(' '*3),'\t\t\t\t\t\t\t[Default]'
	
	time.sleep(0.5)
	print '\n%s19.6 System'%(' '*3),'\t\t\t\t\t\t\t\t\t[Default]'
	print '\n%s+ Ctrl+Alt+Del Options'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	print '\n%s+ Driver Installation'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	print '\n%s+ Folder Redirection'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	print '\n%s+ Group Policy'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	print '\n%s+ Internet Communication Management'%(' '*7)
	time.sleep(0.25)
	print '%s* Internet Communication settings'%(' '*11)
	time.sleep(0.25)
	print '%s> Turn off Help Experience Improvement Program'%(' '*15),'\t\t\t[%s]'%AdministrativeTemplatesUser.NoImplicitFeedback()

	time.sleep(0.5)
	print '\n%s19.7 Windows Components'%(' '*3)
	time.sleep(0.25)
	print '\n%s+ Add features to Windows 8 / 8.1 / 10'%(' '*7),'\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ App runtime'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	print '\n%s+ Application Compatibility'%(' '*7),'\t\t\t\t\t\t[Default]'
	print '\n%s+ Attachment Manager'%(' '*7)
	time.sleep(0.25)
	print '%s* Do not preserve zone information in file attachments'%(' '*11),'\t\t[%s]'%AdministrativeTemplatesUser.SaveZoneInformation()
	print '%s* Notify antivirus programs when opening attachments'%(' '*11),'\t\t[%s]'%AdministrativeTemplatesUser.ScanWithAntiVirus()
	time.sleep(0.4)
	print '\n%s+ AutoPlay Policies'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Backup'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Credential User Interface'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Desktop Gadgets'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Desktop Window Manager'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Digital Locker'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Edge UI'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ EMET'%(' '*7),'\t\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ File Explorer'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ File Revocation'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ IME'%(' '*7),'\t\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Import Video'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Instant Search'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Internet Explorer'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Location and Sensors'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Microsoft Edge'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Microsoft Management Console'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Microsoft Passport for Work'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ NetMeeting'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Network Projector'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Network Sharing'%(' '*7)
	time.sleep(0.25)
	print '%s* Prevent users from sharing files within their profile'%(' '*11),'\t\t[%s]'%AdministrativeTemplatesUser.NoInplaceSharing()
	time.sleep(0.4)
	print '\n%s+ Presentation Settings'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Remote Desktop Services'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ RSS Feeds'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Search'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Sound Recorder'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Store'%(' '*7),'\t\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Tablet PC'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Task Scheduler'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	time.sleep(0.4)
	time.sleep(0.4)
	print '\n%s+ Windows Calendar'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Windows Color System'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Windows Error Reporting'%(' '*7),'\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Windows Installer'%(' '*7)
	time.sleep(0.25)
	print '%s* Always install with elevated privileges'%(' '*11),'\t\t\t\t[%s]'%AdministrativeTemplatesUser.AlwaysInstallElevated()
	time.sleep(0.4)
	print '\n%s+ Windows Logon Options'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Windows Mail'%(' '*7),'\t\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Windows Media Center'%(' '*7),'\t\t\t\t\t\t\t[Default]'
	time.sleep(0.4)
	print '\n%s+ Windows Media Player'%(' '*7)
	time.sleep(0.25)
	print '%s* Networking'%(' '*11),'\t\t\t\t\t\t\t[Default]'
	print '%s* Playback'%(' '*11)
	time.sleep(0.4)
	print '%s> Prevent Codec Download'%(' '*15),'\t\t\t\t\t[%s]'%AdministrativeTemplatesUser.PreventCodecDownload()
#	Summary 
def Summary():
	import types
	time.sleep(0.5)
	print '\t','_'*100,'\n'
	print '\n\t\t\t\t\t','#'*25,'\n','\t\t\t\t\t##       Summary       ##','\n','\t\t\t\t\t','#'*25,'\n'
	time.sleep(0.5)
	# w = g = n = 0
	# t = dir(LocalPolicies)
	print '\t\t\t','_'*57,'\n\t\t\t|\t\t\t\t\t\t\t|'
	print '\t\t\t|\tWARNING\t\t\t\t\t: %s'%CountWarning.warning(),'\t|'
	print '\t\t\t|\t\t\t\t\t\t\t|\n\t\t\t|\tNOT GOOD\t\t\t\t: %s'%CountWarning.notgood(),'\t|'
	print '\t\t\t|\t\t\t\t\t\t\t|\n\t\t\t|\tGOOD or OK\t\t\t\t: %s'%CountWarning.ok(),'\t|'
	print '\t\t\t|\t\t\t\t\t\t\t|\n\t\t\t|\tNOT CONFIG and NOD FOUND\t\t: %s'%CountWarning.notconfig(),'\t|'
	print '\t\t\t|\t\t\t\t\t\t\t|\n\t\t\t|\tDefault\t\t\t\t\t: 215','\t|'
	print '\t\t\t|%s|'%('_'*55),'\n\n\n\n'

	# print '\t\tWARNING : %s'%CountWarning.warning()
	# print '\n\t\tNOT GOOD: %s'%CountWarning.notgood()
	# print '\n\t\tGOOD or OK : %s'%CountWarning.ok()
	# print '\n\t\tNOT CONFIG or NOT FOUND : %s'%CountWarning.notconfig()
def BenchMark():
	print '\n\t\t\t\t\t','#'*25,'\n','\t\t\t\t\t##      BenchMark      ##','\n','\t\t\t\t\t','#'*25,'\n'
	time.sleep(0.5)
	print '\t','_'*100,'\n'
	AccPolicies()
	LocaPolicies()
	Eventlog()
	RestrictedGroups()
	SystemService()
	Registry()
	FileSystem()
	WiredNetwork()
	WindowsFireWall()
	NetWorkListNanagerPolicies()
	WirelessNetwork()
	PuclicKeyPolicies()
	SoftwareRestrictionPolicies()
	NAPClient()
	AppControlPolicies()
	IPSecurity()
	AdAuPoConfig()
	AdTemComputer()
	AdTemUser()


def Export():
	print '\t','_'*100,'\n'
	report.Make()
	print '\n\t\t\t\t\t','#'*25,'\n','\t\t\t\t\t##      ReportHTML     ##','\n','\t\t\t\t\t','#'*25,'\n'
	print '\t\t\t\t Can you see report html in folder Report \n\n\n\n'
	print '\t','_'*100,'\n'
	print '\t','_'*100,'\n'
time.sleep(5)
BenchMark()
time.sleep(5)
SystemInfomation()
Summary()
time.sleep(2)
Export()