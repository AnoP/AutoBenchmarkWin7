################################ 	18.	Administrative Templates ( Computer)		#########################################
from _winreg import *
import os
############	18.1 	Control Panel
############	This section contains recommendations for computer-based administrative templates.
############	18.2	LAPS
def frange(start, stop, step):
	i = start
	while i < stop:
		yield i
		i += step
#   18.2.1	Ensure LAPS AdmPwd GPO Extension / CSE is installed  --> check
def AdmPwd():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}', 0, KEY_ALL_ACCESS)
		value = (QueryValueEx(key,'DllName')[0])
	except:
		return "NOT FOUND"
	temp = 'C:\Program Files\LAPS\CSE\AdmPwd.dll'
	if (value ==temp) == 1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.2.2	Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled'
def PwdExpirationProtection():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft Services\AdmPwd', 0, KEY_READ)
		value = (QueryValueEx(key,'PwdExpirationProtectionEnabled')[0])
	except:
		return "NOT CONFIG"
	if value == 1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.2.3	Ensure 'Enable Local Admin Password Management' is set to 'Enabled'	
def AdmPwdEnabled():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft Services\AdmPwd', 0, KEY_READ)
		value = (QueryValueEx(key,'AdmPwdEnabled')[0])
	except:
		return "NOT CONFIG"
	if value == 1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.2.4	Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters'
def PasswordComplexity():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft Services\AdmPwd', 0, KEY_READ)
		value = (QueryValueEx(key,'PasswordComplexity')[0])
	except:
		return "NOT CONFIG"
	if value == 4 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.2.5	Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more'
def PasswordLength():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft Services\AdmPwd', 0, KEY_READ)
		value = (QueryValueEx(key,'PasswordLength')[0])
	except:
		return "NOT CONFIG"
	if value >= 15 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.2.6	Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer'
def PasswordAgeDays():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft Services\AdmPwd', 0, KEY_READ)
		value = (QueryValueEx(key,'PasswordAgeDays')[0])
	except:
		return "NOT FOUND"
	if value <= 30 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

##########	18.3	MSS ( Legacy )    -> check
#	18.3.1 Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'
def AutoAdminLogon():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon', 0, KEY_READ)
		value = (QueryValueEx(key,'AutoAdminLogon')[0])
	except:
		return "NOT FOUND"
	if value == 0 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.3.2 Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
def DisableIP6SourceRouting():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\Tcpip6\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'DisableIPSourceRouting')[0])
	except:
		return "NOT FOUND"
	if value == 0 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.3.3 Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
def DisableIPSourceRouting():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\Tcpip\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'DisableIPSourceRouting')[0])
	except:
		return "NOT FOUND"
	if value == 1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.3.4 Ensure 'MSS: (DisableSavePassword) Prevent the dial-up password from being saved' is set to 'Enabled'
def Disablesavepassword():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\RasMan\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'disablesavepassword')[0])
	except:
		return "NOT FOUND"
	if value == 1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.3.5 Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'
def EnableICMPRedirect():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\Tcpip\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'EnableICMPRedirect')[0])
	except:
		return "NOT FOUND"
	if value == 0 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.3.6 Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'
def KeepAliveTime():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\Tcpip\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'KeepAliveTime')[0])
	except:
		return "NOT FOUND"
	if value == 1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#	18.3.7 Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'
def Nonamereleaseondemand():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\NetBT\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'nonamereleaseondemand')[0])
	except:
		return "NOT FOUND"
	if value == 1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.3.8 Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' is set to 'Disabled'	
def PerformRouterDiscovery():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\Tcpip\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'PerformRouterDiscovery')[0])
	except:
		return "NOT FOUND"
	if value == 0 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.3.9 Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'
def SafeDllSearchMode():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\Session Manager', 0, KEY_READ)
		value = (QueryValueEx(key,'SafeDllSearchMode')[0])
	except:
		return "NOT FOUND"
	if value == 1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.3.10 Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'
def ScreenSaverGracePeriod():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows NT\CurrentVersion\Winlogon', 0, KEY_READ)
		value = (QueryValueEx(key,'ScreenSaverGracePeriod')[0])
	except:
		return "NOT FOUND"
	if value <= 5 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#	18.3.11 Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
def Tcpmaxdataretransmissions6():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\TCPIP6\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'tcpmaxdataretransmissions')[0])
	except:
		return "NOT FOUND"
	if value == 3 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.3.12 Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
def Tcpmaxdataretransmissions():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Services\Tcpip\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'tcpmaxdataretransmissions')[0])
	except:
		return "NOT FOUND"
	if value == 3 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#	18.3.13 Ensure 'MSS: (WARNINGLevel) Percentage threshold for the security event log at which the system will generate a WARNING' is set to 'Enabled: 90% or less'
def WARNINGLevel():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\Eventlog\Security', 0, KEY_READ)
		value = (QueryValueEx(key,'WARNINGLevel')[0])
	except:
		return "NOT FOUND"
	if value == 1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

##########	18.4	Network
#	18.4.1	Background Intelligent Transfer Service (BITS)
#	18.4.2	BranchCache
#	18.4.3	DirectAccess Client Experience Settings
#	18.4.4	DNS Client
#	18.4.5	Hotspot Authentication
#	18.4.6	Lanman Server
#	18.4.7	Lanman Workstation
#	18.4.8	Link-Layer Topology Discovery
#		18.4.8.1	Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'
def TurnonMapperIO():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\LLTD', 0, KEY_READ)
		value0 = (QueryValueEx(key,'AllowLLTDIOOnDomain'))[0]
		value1 = (QueryValueEx(key,'AllowLLTDIOOnPublicNet'))[0]
		value2 = (QueryValueEx(key,'EnableLLTDIO'))[0]
		value3 = (QueryValueEx(key,'ProhibitLLTDIOOnPrivateNet'))[0]
	except:
		return "NOT CONFIG"
	if (value0 == 0 and value1 == 0 and value2 == 0 and value3 == 0):
		return 'GOOD'
	return 'WARNING'
	CloseKey(key)

#		18.4.8.2	Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'
def TurnonResponder():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\LLTD', 0, KEY_READ)
		value0 = (QueryValueEx(key,'AllowRspndrOnDomain'))[0]
		value1 = (QueryValueEx(key,'AllowRspndrOnPublicNet'))[0]
		value2 = (QueryValueEx(key,'EnableRspndr'))[0]
		value3 = (QueryValueEx(key,'ProhibitRspndrOnPrivateNet'))[0]
	except:
		return "NOT CONFIG"
	if (value0 == 0 and value1 == 0 and value2 == 0 and value3 == 0):
		return 'GOOD'
	return 'WARNING'
	CloseKey(key)

#	18.4.9	Microsoft Peer-to-Peer Networking Services	
#		18.4.9.1 Peer Name Resolution Protocol
#		18.4.9.2 Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'
def Peernet():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Peernet', 0, KEY_READ)
		value = (QueryValueEx(key,'Disabled')[0])
	except:
		return "NOT FOUND"
	if value == 1 :
		return 'GOOD'
	return 'WARNING';
	CloseKey(key)

#	18.4.10 Network Connections
#		18.4.10.1 Windows Firewall
#		18.4.10.2 Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
def NCAllowNetBridgeNLA():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\Network Connections', 0, KEY_READ)
		value = (QueryValueEx(key,'NC_AllowNetBridge_NLA')[0])
	except:
		return "NOT CONFIG"
	if value == 0 :
		return 'GOOD'
	return 'WARNING';
	CloseKey(key)

#		18.4.10.3 Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'
def NCStdDomainUserSetLocation():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\Network Connections', 0, KEY_READ)
		value = (QueryValueEx(key,'NC_StdDomainUserSetLocation')[0])
	except:
		return "NOT CONFIG"
	if value == 1 :
		return 'GOOD'
	return 'WARNING';
	CloseKey(key)

#	18.4.11 Network Connectivity Status Indicator
#	18.4.12 Network Isolation
#	18.4.13 Network Provider  ->> check
#		18.4.13.1 Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares'
def HardenedPaths():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths', 0, KEY_READ)
		value0 = (QueryValueEx(key,'\*\NETLOGON')[0])
		value1 = (QueryValueEx(key,'\\*\SYSVOL')[0])
	except:
		return "NOT CONFIG"
	if value0 == 1 and value1 == 1:
		return 'GOOD'
	return 'WARNING';
	CloseKey(key)

# 	18.4.14 Offline Files
#	18.4.15 QoS Packet Scheduler
#	18.4.16 SNMP
#	18.4.17 SSL Configuration Settings
#	18.4.18 TCPIP Settings
#		18.4.18.1 IPv6 Transition Technologies
#		18.4.18.2 Parameters
#			18.4.18.2.1 Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')	
def DisabledComponents():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters', 0, KEY_READ)
		value = (QueryValueEx(key,'DisabledComponents')[0])
	except:
		return "Not Set Registry"
	if value == 255 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.4.19 Windows Connect Now
#		18.4.19.1 Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'
def Registrars():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\WCN\Registrars', 0, KEY_READ)
		value0 = (QueryValueEx(key,'EnableRegistrars')[0])
		value1 = (QueryValueEx(key,'DisableUPnPRegistrar')[0])
		value2 = (QueryValueEx(key,'DisableInBand802DOT11Registrar')[0])
		value3 = (QueryValueEx(key,'DisableFlashConfigRegistrar')[0])
		value4 = (QueryValueEx(key,'DisableWPDRegistrar')[0])
	except:
		return "NOT CONFIG"
	if value0 == value1 == value2 == value3 == value4 == 0:
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#		18.4.19.2 Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'
def DisableWcnUi():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\WCN\UI', 0, KEY_READ)
		value = (QueryValueEx(key,'DisableWcnUi')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

##########	18.5 Printers
##########	18.6 SCM: Pass the Hash Mitigations --> check value
#	18.6.1 Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'
def LocalAccountTokenFilterPolicy():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\System', 0, KEY_READ)
		value = (QueryValueEx(key,'LocalAccountTokenFilterPolicy')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.6.2 Ensure 'WDigest Authentication' is set to 'Disabled'
def UseLogonCredential():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest', 0, KEY_READ)
		value = (QueryValueEx(key,'UseLogonCredential')[0])
	except:
		return "NOT CONFIG"
	if value ==  0 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

##########	18.7 Start Menu and Taskbar
##########	18.8 System
#	18.8.1 Access-Denied Assistance
#	18.8.2 Audit Process Creation --> check value
#		18.8.2.1 Ensure 'Include command line in process creation events' is set to 'Disabled' 
def ProcessCreationIncludeCmdLineEnabled():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit', 0, KEY_READ)
		value = (QueryValueEx(key,'ProcessCreationIncludeCmdLine_Enabled')[0])
	except:
		return "NOT CONFIG"
	if value ==  0 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.8.3 Credentials Delegation
#	18.8.4 Device Guard
#	18.8.5 Device Installation
#		18.8.5.1 Device Installation Restrictions --> check
#			18.8.5.1.1 Ensure 'Prevent installation of devices using drivers that match these device setup classes' is set to 'Enabled'
def DenyDeviceClasses():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions', 0, KEY_READ)
		value = (QueryValueEx(key,'DenyDeviceClasses')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)
#			18.8.5.1.2 Ensure 'Prevent installation of devices using drivers that match these device setup classes: Prevent installation of devices using drivers for these device setup' is set to '{d48179be-ec20-11d1-b6b8-00c04fa372a7}'
def DenyDeviceClasses1():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses', 0, KEY_READ)
		value = (QueryValueEx(key,'1')[0])
	except:
		return "NOT CONFIG"
	temp = '{d48179be-ec20-11d1-b6b8-00c04fa372a7}'
	if (value == temp) == 1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.8.5.1.3 Ensure 'Prevent installation of devices using drivers that match these device setup classes: Also apply to matching devices that are already installed.' is set to 'True' (checked)
def DenyDeviceClassesRetroactive():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions', 0, KEY_READ)
		value = (QueryValueEx(key,'DenyDeviceClassesRetroactive')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#		18.8.5.2 Ensure 'Allow remote access to the Plug and Play interface' is set to 'Disabled'
def AllowRemoteRPC():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\DeviceInstall\Settings', 0, KEY_READ)
		value = (QueryValueEx(key,'AllowRemoteRPC')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.8.6 Device Redirection
#	18.8.7 Disk NV Cache
#	18.8.9 Distributed COM
#	18.8.10 Driver Installation
#	18.8.11 Early Launch Antimalware
#	18.8.12 Enhanced Storage Access
#	18.8.13 File Classification Infrastructure
#	18.8.14 File Share Shadow Copy Agent
#	18.8.15 File Share Shadow Copy Provider
#	18.8.16 Filesystem
#	18.8.17 Folder Redirection
#	18.8.18 Group Policy
#		18.8.18.1 Logging and tracing
#		18.8.18.2 Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
def NoBackgroundPolicy():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}', 0, KEY_READ)
		value = (QueryValueEx(key,'NoBackgroundPolicy')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#		18.8.18.3 Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'
def NoGPOListChanges():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}', 0, KEY_READ)
		value = (QueryValueEx(key,'NoGPOListChanges')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)
#		--> check
#		18.8.18.4 Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled' (Scored)
def DisableBkGndGroupPolicy():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 0, KEY_READ)
		value = (QueryValueEx(key,'DisableBkGndGroupPolicy')[0])
	except:
		return "NOT CONFIG"
	if value ==  0 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.8.19 Internet Communication Management
#		18.8.19.1 Internet Communication settings
#			18.8.19.1.1 Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled' --> check
def DisableWebPnPDownload(): 
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows NT\Printers', 0, KEY_READ)
		value = (QueryValueEx(key,'DisableWebPnPDownload')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.8.19.1.2 Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled' --> check
def PreventHandwritingDataSharing():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows NT\TabletPC', 0, KEY_READ)
		value = (QueryValueEx(key,'PreventHandwritingDataSharing')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.8.19.1.3 Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
def PreventHandwritingErrorReports():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\HandwritingErrorReports', 0, KEY_READ)
		value = (QueryValueEx(key,'PreventHandwritingErrorReports')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.8.19.1.4 Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'
def ExitOnMSICW():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\Internet Connection Wizard', 0, KEY_READ)
		value = (QueryValueEx(key,'ExitOnMSICW')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.8.19.1.5 Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
def NoWebServices():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', 0, KEY_READ)
		value = (QueryValueEx(key,'NoWebServices')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.8.19.1.6 Ensure 'Turn off Internet File Association service' is set to 'Enabled'
def NoInternetOpenWith():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', 0, KEY_READ)
		value = (QueryValueEx(key,'NoInternetOpenWith')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#			18.8.19.1.7 Ensure 'Turn off printing over HTTP' is set to 'Enabled'
def DisableHTTPPrinting():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows NT\Printers', 0, KEY_READ)
		value = (QueryValueEx(key,'DisableHTTPPrinting')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.8.19.1.8 Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'
def NoRegistration():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\Registration Wizard Control', 0, KEY_READ)
		value = (QueryValueEx(key,'NoRegistration')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.8.19.1.9 Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
def DisableContentFileUpdates():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\SearchCompanion', 0, KEY_READ)
		value = (QueryValueEx(key,'DisableContentFileUpdates')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.8.19.1.10 Ensure 'Turn off the "Order Prints" picture task' is set to 'Enabled'
def NoOnlinePrintsWizard():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', 0, KEY_READ)
		value = (QueryValueEx(key,'NoOnlinePrintsWizard')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.8.19.1.11 Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
def NoPublishingWizard():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', 0, KEY_READ)
		value = (QueryValueEx(key,'NoPublishingWizard')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.8.19.1.12 Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
def CEIP():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Messenger\Client', 0, KEY_READ)
		value = (QueryValueEx(key,'CEIP')[0])
	except:
		return "NOT CONFIG"
	if value ==  2 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.8.19.1.13 Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
def CEIPEnable():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\SQMClient\Windows', 0, KEY_READ)
		value = (QueryValueEx(key,'CEIPEnable')[0])
	except:
		return "NOT CONFIG"
	if value ==  0 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.8.19.1.14 Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
def WindowsErrorReporting():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\Windows Error Reporting', 0, KEY_READ)
		value = (QueryValueEx(key,'Disabled')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.8.20 iSCSI
#	18.8.21 KDC
#	18.8.22 Kerberos
#	18.8.23 Locale Services
#	18.8.24 Logon
#		18.8.24.1 Ensure 'Always use classic logon' is set to 'Enabled'
def LogonType():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\System', 0, KEY_READ)
		value = (QueryValueEx(key,'LogonType')[0])
	except:
		return "NOT CONFIG"
	if value ==  0 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.8.25 Mitigation Options
#	18.8.26 Net Logon
#	18.8.27 Performance Control Panel
#	18.8.28 Power Management
#		18.8.28.1 Button Settings
#		18.8.28.2 Hard Disk Settings
#		18.8.28.3 Notification Settings
#		18.8.28.4 Sleep Settings
#			18.8.28.4.1 Ensure 'Allow standby states (S1-S3) when sleeping (on battery)' is set to 'Disabled'
def DCSettingIndex():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab', 0, KEY_READ)
		value = (QueryValueEx(key,'DCSettingIndex')[0])
	except:
		return "NOT CONFIG"
	if value ==  0 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.8.28.4.2 Ensure 'Allow standby states (S1-S3) when sleeping (plugged in)' is set to 'Disabled'
def ACSettingIndex():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab', 0, KEY_READ)
		value = (QueryValueEx(key,'ACSettingIndex')[0])
	except:
		return "NOT CONFIG"
	if value ==  0 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.8.28.4.3 Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'
def DCSettingIndex1():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51', 0, KEY_READ)
		value = (QueryValueEx(key,'DCSettingIndex')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.8.28.4.4 Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'		
def ACSettingIndex1():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51', 0, KEY_READ)
		value = (QueryValueEx(key,'ACSettingIndex')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.8.29 Recovery
#	18.8.30 Remote Assistance 
#		18.8.30.1 Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'	
def fAllowUnsolicited():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\policies\Microsoft\Windows NT\Terminal Services', 0, KEY_READ)
		value = (QueryValueEx(key,'fAllowUnsolicited')[0])
	except:
		return "NOT CONFIG"
	if value ==  0 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#		18.8.30.2 Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'	
def fAllowToGetHelp():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\policies\Microsoft\Windows NT\Terminal Services', 0, KEY_READ)
		value = (QueryValueEx(key,'fAllowToGetHelp')[0])
	except:
		return "NOT CONFIG"
	if value ==  0 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.8.31 Remote Procedure Call
#		18.8.31.1 Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'
def EnableAuthEpResolution():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows NT\Rpc', 0, KEY_READ)
		value = (QueryValueEx(key,'EnableAuthEpResolution')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#		18.8.31.2 Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'
def RestrictRemoteClients():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows NT\Rpc', 0, KEY_READ)
		value = (QueryValueEx(key,'RestrictRemoteClients')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.8.32 Removable Storage Access
#	18.8.33 Scripts
#	18.8.34 Server Manager
#	18.8.35 Shutdown
#	18.8.36 Shutdown Options
#	18.8.37 System Restore
#	18.8.38 Troubleshooting and Diagnostics
#		18.8.38.1 Application Compatibility Diagnostics
#		18.8.38.2 Corrupted File Recovery
#		18.8.38.3 Disk Diagnostic
#		18.8.38.4 Fault Tolerant Heap
#		18.8.38.5 Microsoft Support Diagnostic Tool
#			18.8.38.5.1 Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'
def DisableQueryRemoteServer():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy', 0, KEY_READ)
		value = (QueryValueEx(key,'DisableQueryRemoteServer')[0])
	except:
		return "NOT CONFIG"
	if value ==  0 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#		18.8.38.6 MSI Corrupted File Recovery
#		18.8.38.7 Scheduled Maintenance
#		18.8.38.8 Scripted Diagnostics
#		18.8.38.9 Windows Boot Performance Diagnostics
#		18.8.38.10 Windows Memory Leak Diagnosis
#		18.8.38.11 Windows Performance PerfTrack
#			18.8.38.11.1 Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'
def ScenarioExecutionEnabled():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}', 0, KEY_READ)
		value = (QueryValueEx(key,'ScenarioExecutionEnabled')[0])
	except:
		return "NOT CONFIG"
	if value ==  0 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)


#	18.8.39 Trusted Platform Module Services
#	18.8.40 User Profiles
#	18.8.41 Windows File Protection
#	18.8.42 Windows HotStart
#	18.8.43 Windows Time Service
#		18.8.43.1 Time Providers
#			18.8.43.1.1 Ensure 'Enable Windows NTP Client' is set to 'Enabled'
def NtpClient():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient', 0, KEY_READ)
		value = (QueryValueEx(key,'Enabled')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#		18.8.43.1.2 Ensure 'Enable Windows NTP Server' is set to 'Disabled'
def NtpServer():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer', 0, KEY_READ)
		value = (QueryValueEx(key,'Enabled')[0])
	except:
		return "NOT CONFIG"
	if value ==  0 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

##########	18.9 Windows Components
#	18.9.1 Active Directory Federation Services
#	18.9.2 ActiveX Installer Service
#	18.9.3 Add features to Windows 8 / 8.1 / 10	
#	18.9.4 App Package Deployment
#	18.9.5 App Privacy
#	18.9.6 App runtime
#	18.9.7 Application Compatibility
#	18.9.8 AutoPlay Policies
#		18.9.8.1 Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'
def NoAutoplayfornonVolume():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\Explorer', 0, KEY_READ)
		value = (QueryValueEx(key,'NoAutoplayfornonVolume')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#		18.9.8.2 Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'
def NoAutorun():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer', 0, KEY_READ)
		value = (QueryValueEx(key,'NoAutorun')[0])
	except:
		return "NOT CONFIG"
	if value ==  1 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#		18.9.8.3 Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'	
def NoDriveTypeAutoRun():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', 0, KEY_READ)
		value = (QueryValueEx(key,'NoDriveTypeAutoRun')[0])
	except:
		return "NOT CONFIG"
	if value ==  255 :
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.9.9 Backup
#	18.9.10 Biometrics
#	18.9.11 BitLocker Drive Encryption
#		18.9.11.1 Fixed Data Drives
#			18.9.11.1.1 Ensure 'Allow access to BitLocker-protected fixed data drives from earlier versions of Windows' is set to 'Disabled'	
def FDVDiscoveryVolumeType():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'FDVDiscoveryVolumeType')[0])
	except:
		return "NOT CONFIG"
	temp = '<none>'
	if (value ==  temp) == 1:
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.1.2 Ensure 'Choose how BitLocker-protected fixed drives can be recovered' is set to 'Enabled'	
def FDVRecovery():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'FDVRecovery')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.1.3 Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Allow data recovery agent' is set to 'Enabled: True'	
def FDVManageDRA():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'FDVManageDRA')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.1.4 Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Recovery Password' is set to 'Enabled: Allow 48-digit recovery password'	
def FDVRecoveryPassword():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'FDVRecoveryPassword')[0])
	except:
		return "NOT CONFIG"
	if (value == 2):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.1.5 Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Recovery Key' is set to 'Enabled: Allow 256-bit recovery key'
def FDVRecoveryKey():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'FDVRecoveryKey')[0])
	except:
		return "NOT CONFIG"
	if (value == 2):
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#			18.9.11.1.6 Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'
def FDVHideRecoveryPage():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'FDVHideRecoveryPage')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.1.7 Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Save BitLocker recovery information to AD DS for fixed data drives' is set to 'Enabled: False'
def FDVActiveDirectoryBackup():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'FDVActiveDirectoryBackup')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#			18.9.11.1.8 Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Configure storage of BitLocker recovery information to AD DS' is set to 'Enabled: Backup recovery passwords and key packages'
def FDVActiveDirectoryInfoToStore():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'FDVActiveDirectoryInfoToStore')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.1.9 Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for fixed data drives' is set to 'Enabled: False'
def FDVRequireActiveDirectoryBackup():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'FDVRequireActiveDirectoryBackup')[0])
	except:
		return "NOT CONFIG"
	if (value == 0):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.1.10 Ensure 'Configure use of passwords for fixed data drives' is set to 'Disabled'	
def FDVPassphrase():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'FDVPassphrase')[0])
	except:
		return "NOT CONFIG"
	if (value == 0):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.1.11 Ensure 'Configure use of smart cards on fixed data drives' is set to 'Enabled'
def FDVAllowUserCert():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'FDVAllowUserCert')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.1.12 Ensure 'Configure use of smart cards on fixed data drives: Require use of smart cards on fixed data drives' is set to 'Enabled: True'
def FDVEnforceUserCert():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'FDVEnforceUserCert')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#		18.9.11.2 Operating System Drives
#			18.9.11.2.1 Ensure 'Allow enhanced PINs for startup' is set to 'Enabled'
def UseEnhancedPin():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'UseEnhancedPin')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.2.2 Ensure 'Choose how BitLocker-protected operating system drives can be recovered' is set to 'Enabled'
def OSRecovery():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'OSRecovery')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.2.3 Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Allow data recovery agent' is set to 'Enabled: False'
def OSManageDRA():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'OSManageDRA')[0])
	except:
		return "NOT CONFIG"
	if (value == 0):
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#			18.9.11.2.4 Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Password' is set to 'Enabled: Require 48-digit recovery password'
def OSRecoveryPassword():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'OSRecoveryPassword')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.2.5 Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key'
def OSRecoveryKey():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'OSRecoveryKey')[0])
	except:
		return "NOT CONFIG"
	if (value == 0):
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#			18.9.11.2.6 Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'
def OSHideRecoveryPage():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'OSHideRecoveryPage')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#			18.9.11.2.7 Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Save BitLocker recovery information to AD DS for operating system drives' is set to 'Enabled: True'	
def OSActiveDirectoryBackup():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'OSActiveDirectoryBackup')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.2.8 Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Store recovery passwords and key packages'			
def OSActiveDirectoryInfoToStore():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'OSActiveDirectoryInfoToStore')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.2.9 Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for operating system drives' is set to 'Enabled: True'
def OSRequireActiveDirectoryBackup():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'OSRequireActiveDirectoryBackup')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.2.10 Ensure 'Configure minimum PIN length for startup' is set to 'Enabled: 7 or more characters'
def MinimumPIN():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'MinimumPIN')[0])
	except:
		return "NOT CONFIG"
	if (value == 7):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.2.11 Ensure 'Require additional authentication at startup' is set to 'Enabled'
def UseAdvancedStartup():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'UseAdvancedStartup')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.2.12 Ensure 'Require additional authentication at startup: Allow BitLocker without a compatible TPM' is set to 'Enabled: False'
def EnableBDEWithNoTPM():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'EnableBDEWithNoTPM')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.2.13 Ensure 'Require additional authentication at startup: Configure TPM startup:' is set to 'Enabled: Do not allow TPM'
def UseTPM():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'UseTPM')[0])
	except:
		return "NOT CONFIG"
	if (value == 0):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.2.14 Ensure 'Require additional authentication at startup: Configure TPM startup PIN:' is set to 'Enabled: Require startup PIN with TPM'
def UseTPMPIN():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'UseTPMPIN')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.2.15 Ensure 'Require additional authentication at startup: Configure TPM startup key:' is set to 'Enabled: Do not allow startup key with TPM'
def UseTPMKey():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'UseTPMKey')[0])
	except:
		return "NOT CONFIG"
	if (value == 0):
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#			18.9.11.2.16 (BL) Ensure 'Require additional authentication at startup: Configure TPM startup key and PIN:' is set to 'Enabled: Do not allow startup key and PIN with TPM'	
def UseTPMKeyPIN():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'UseTPMKeyPIN')[0])
	except:
		return "NOT CONFIG"
	if (value == 0):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#		18.9.11.3 Removable Data Drives
#			18.9.11.3.1 Ensure 'Allow access to BitLocker-protected removable data drives from earlier versions of Windows' is set to 'Disabled'
def RDVDiscoveryVolumeType():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'RDVDiscoveryVolumeType')[0])
	except:
		return "NOT CONFIG"
	temp = '<none>'
	if (value ==temp) == 1:
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.3.2 Ensure 'Choose how BitLocker-protected removable drives can be recovered' is set to 'Enabled'
def RDVRecovery():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'RDVRecovery')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.3.3 Ensure 'Choose how BitLocker-protected removable drives can be recovered: Allow data recovery agent' is set to 'Enabled: True'
def RDVManageDRA():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'RDVManageDRA')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.3.4 Ensure 'Choose how BitLocker-protected removable drives can be recovered: Recovery Password' is set to 'Enabled: Do not allow 48-digit recovery password'
def RDVRecoveryPassword():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'RDVRecoveryPassword')[0])
	except:
		return "NOT CONFIG"
	if (value == 0):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.3.5 Ensure 'Choose how BitLocker-protected removable drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key'
def RDVRecoveryKey():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'RDVRecoveryKey')[0])
	except:
		return "NOT CONFIG"
	if (value == 0):
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#			18.9.11.3.6 Ensure 'Choose how BitLocker-protected removable drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True'
def RDVHideRecoveryPage():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'RDVHideRecoveryPage')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#			18.9.11.3.7 Ensure 'Choose how BitLocker-protected removable drives can be recovered: Save BitLocker recovery information to AD DS for removable data drives' is set to 'Enabled: False'
def RDVActiveDirectoryBackup():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'RDVActiveDirectoryBackup')[0])
	except:
		return "NOT CONFIG"
	if (value == 0):
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#			18.9.11.3.8 Ensure 'Choose how BitLocker-protected removable drives can be recovered: Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Backup recovery passwords and key packages'
def RDVActiveDirectoryInfoToStore():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'RDVActiveDirectoryInfoToStore')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.3.9 Ensure 'Choose how BitLocker-protected removable drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for removable data drives' is set to 'Enabled: False'
def RDVRequireActiveDirectoryBackup():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'RDVRequireActiveDirectoryBackup')[0])
	except:
		return "NOT CONFIG"
	if (value == 0):
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#			18.9.11.3.10 Ensure 'Configure use of passwords for removable data drives' is set to 'Disabled'
def RDVPassphrase():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'RDVPassphrase')[0])
	except:
		return "NOT CONFIG"
	if (value == 0):
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#			18.9.11.3.11 Ensure 'Configure use of smart cards on removable data drives' is set to 'Enabled'	
def RDVAllowUserCert():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'RDVAllowUserCert')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#			18.9.11.3.12 Ensure 'Configure use of smart cards on removable data drives: Require use of smart cards on removable data drives' is set to 'Enabled: True'
def RDVEnforceUserCert():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'RDVEnforceUserCert')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.3.13 Ensure 'Deny write access to removable drives not protected by BitLocker' is set to 'Enabled'
def RDVDenyWriteAccess():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'System\CurrentControlSet\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'RDVDenyWriteAccess')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#			18.9.11.3.14 Ensure 'Deny write access to removable drives not protected by BitLocker: Do not allow write access to devices configured in another organization' is set to 'Enabled: False'		
def RDVDenyCrossOrg():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'RDVDenyCrossOrg')[0])
	except:
		return "NOT CONFIG"
	if (value == 0):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#		18.9.11.4 Ensure 'Choose drive encryption method and cipher strength (Windows Vista, Windows Server 2008, Windows 7, Windows Server 2008 R2)' is set to 'Enabled: AES 256-bit with Diffuser'
def EncryptionMethod():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\FVE', 0, KEY_READ)
		value = (QueryValueEx(key,'EncryptionMethod')[0])
	except:
		return "NOT CONFIG"
	if (value == 2):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.9.12 Cloud Content
#	18.9.13 Credential User Interface
#		18.9.13.1 Ensure 'Do not display the password reveal button' is set to 'Enabled'	--> check
def DisablePasswordReveal():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\CredUI', 0, KEY_READ)
		value = (QueryValueEx(key,'DisablePasswordReveal')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#		18.9.13.2 Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'
def EnumerateAdministrators():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Policies\CredUI', 0, KEY_READ)
		value = (QueryValueEx(key,'EnumerateAdministrators')[0])
	except:
		return "NOT CONFIG"
	if (value == 0):
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#	18.9.14 Data Collection and Preview Builds
#	18.9.15 Delivery Optimization
#	18.9.16 Desktop Gadgets
#		18.9.16.1 Ensure 'Turn off desktop gadgets' is set to 'Enabled'
def TurnOffSidebar():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar', 0, KEY_READ)
		value = (QueryValueEx(key,'TurnOffSidebar')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#		18.9.16.2 Ensure 'Turn Off user-installed desktop gadgets' is set to 'Enabled'
def TurnOffUserInstalledGadgets():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar', 0, KEY_READ)
		value = (QueryValueEx(key,'TurnOffUserInstalledGadgets')[0])
	except:
		return "NOT CONFIG"
	if (value == 1):
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.9.17 Desktop Window Manager
#	18.9.18 Device and Driver Compatibility
#	18.9.19 Device Registration (formerly Workplace Join)
#	18.9.20 Digital Locker
#	18.9.21 Edge UI
#	18.9.22 EMET
#		18.9.22.1 Ensure 'EMET 5.5' or higher is installed --> check check
def EMETInstall():
	for i in frange(5.5,10,0.5):
		temp = r'C:\Program Files (x86)\EMET %s'%i
		if os.path.exists(temp):
			return 'OK'
	return 'NOT CONFIG' 
#		18.9.22.2 Ensure 'Default Action and Mitigation Settings' is set to 'Enabled' (plus subsettings) --> check
def SysSettings():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\EMET\SysSettings', 0, KEY_READ)
		value0 = (QueryValueEx(key,'AntiDetours')[0])
		value1 = (QueryValueEx(key,'BannedFunctions')[0])
		value2 = (QueryValueEx(key,'DeepHooks')[0])
		value3 = (QueryValueEx(key,'ExploitAction')[0])
	except:
		return "NOT CONFIG"
	if value0 == 1 and value1 == 1 and value2 == 1 and value3 == 1:
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#		18.9.22.3 Ensure 'Default Protections for Internet Explorer' is set to 'Enabled'	--> check
def IE():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\EMET\Defaults', 0, KEY_READ)
		value = (QueryValueEx(key,'IE')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#		18.9.22.4 Ensure 'Default Protections for Popular Software' is set to 'Enabled'	--> check
def Defaults():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\EMET', 0, KEY_READ)
		value = (QueryValueEx(key,'Defaults')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING';
	CloseKey(key)
	
#		18.9.22.5 Ensure 'Default Protections for Recommended Software' is set to 'Enabled' -> check
def Defaults1():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\EMET', 0, KEY_READ)
		value = (QueryValueEx(key,'Defaults')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#		18.9.22.6 Ensure 'System ASLR' is set to 'Enabled: Application Opt-In' -> check
def ASLR():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\EMET\SysSettings', 0, KEY_READ)
		value = (QueryValueEx(key,'ASLR')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#		18.9.22.7 Ensure 'System DEP' is set to 'Enabled: Application Opt-Out' -> check
def DEP():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\EMET\SysSettings', 0, KEY_READ)
		value = (QueryValueEx(key,'DEP')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#		18.9.22.8 Ensure 'System SEHOP' is set to 'Enabled: Application Opt-Out' --> check
def SEHOP():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\EMET\SysSettings', 0, KEY_READ)
		value = (QueryValueEx(key,'SEHOP')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING';
	CloseKey(key)

#	18.9.23 Event Forwarding	
#	18.9.24 Event Log Service
#		18.9.24.1 Application
#			18.9.24.1.1 Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
def Retention():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\EventLog\Application', 0, KEY_READ)
		value = int(QueryValueEx(key,'Retention')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#			18.9.24.1.2 Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
def MaxSize():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\EventLog\Application', 0, KEY_READ)
		value =	(QueryValueEx(key,'MaxSize')[0])
	except:
		return "NOT CONFIG"
	if value >= 32768:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#		18.9.24.2 Security
#			18.9.24.2.1 Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
def Retention1():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\EventLog\Security', 0, KEY_READ)
		value = int(QueryValueEx(key,'Retention')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#			18.9.24.2.2 Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'
def MaxSize1():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\EventLog\Security', 0, KEY_READ)
		value = (QueryValueEx(key,'MaxSize')[0])
	except:
		return "NOT CONFIG"
	if value >= 196608:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#		18.9.24.3 Setup	
#			18.9.24.3.1 Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
def Retention2():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\EventLog\Setup', 0, KEY_READ)
		value = int(QueryValueEx(key,'Retention')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#			18.9.24.3.2 Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
def MaxSize2():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\EventLog\Setup', 0, KEY_READ)
		value = (QueryValueEx(key,'MaxSize')[0])
	except:
		return "NOT CONFIG"
	if value >= 32768:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#		18.9.24.4 System
#			18.9.24.4.1 Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
def Retention3():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\EventLog\System', 0, KEY_READ)
		value = int(QueryValueEx(key,'Retention')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#			18.9.24.4.2 Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
def MaxSize3():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\EventLog\System', 0, KEY_READ)
		value = (QueryValueEx(key,'MaxSize')[0])
	except:
		return "NOT CONFIG"
	if value >= 32768:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#		18.9.25 Event Logging
#		18.9.26 Event Viewer
#		18.9.27 Family Safety
#		18.9.28 File Explorer
#			18.9.28.1 Previous Versions
#			18.9.28.2 Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
def NoDataExecutionPrevention():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\Explorer', 0, KEY_READ)
		value = (QueryValueEx(key,'NoDataExecutionPrevention')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#			18.9.28.3 Ensure 'Turn off heap termination on corruption' is set to 'Disabled'	
def NoHeapTerminationOnCorruption():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\Explorer', 0, KEY_READ)
		value = (QueryValueEx(key,'NoHeapTerminationOnCorruption')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
	
#			18.9.28.4 Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'
def PreXPSP2ShellProtocolBehavior():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\Explorer', 0, KEY_READ)
		value = (QueryValueEx(key,'PreXPSP2ShellProtocolBehavior')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#	18.9.29 File History	
#	18.9.30 Game Explorer
#	18.9.31 HomeGroup
#		18.9.31.1 Ensure 'Prevent the computer from joining a homegroup' is set to 'Enabled'
def DisableHomeGroup():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\HomeGroup', 0, KEY_READ)
		value = (QueryValueEx(key,'DisableHomeGroup')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
	
#	18.9.32 Import Video
#	18.9.33 Internet Explorer
#	18.9.34 Internet Information Services
#	18.9.35 Location and Sensors
#		18.9.35.1 Ensure 'Turn off location' is set to 'Enabled'
def DisableLocation():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors', 0, KEY_READ)
		value = (QueryValueEx(key,'DisableLocation')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#	18.9.36 Maintenance Scheduler
#	18.9.37 Maps
#	18.9.38 Microsoft Edge
#	18.9.39 Microsoft Passport for Work
#	18.9.40 NetMeeting
#	18.9.41 Network Access Protection
#	18.9.42 Network Projector
#	18.9.43 OneDrive
#	18.9.44 Online Assistance
#	18.9.45 Password Synchronization
#	18.9.46 Portable Operating System
#	18.9.47 Presentation Settings
#	18.9.48 Remote Desktop Services (formerly Terminal Services)
#		18.9.48.1 RD Licensing
#		18.9.48.2 Remote Desktop Connection Client
#			18.9.48.2.1 RemoteFX USB Device Redirection
#			18.9.48.2.2 Ensure 'Do not allow passwords to be saved' is set to 'Enabled'
def DisablePasswordSaving():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 0, KEY_READ)
		value = (QueryValueEx(key,'DisablePasswordSaving')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#		18.9.48.3 Remote Desktop Session Host		
#			18.9.48.3.1 Application Compatibility
#			18.9.48.3.2 Connections
#				18.9.48.3.2.1 Ensure 'Allow users to connect remotely by using Remote Desktop Services' is set to 'Disabled'
def fDenyTSConnections():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\Terminal Server', 0, KEY_READ)
		value = (QueryValueEx(key,'fDenyTSConnections')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#			18.9.48.3.3 Device and Resource Redirection		
#				18.9.48.3.3.1 Ensure 'Do not allow COM port redirection' is set to 'Enabled'	
def fDisableCcm():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 0, KEY_READ)
		value = (QueryValueEx(key,'fDisableCcm')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
	
#				18.9.48.3.3.2 Ensure 'Do not allow drive redirection' is set to 'Enabled'
def fDisableCdm():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 0, KEY_READ)
		value = (QueryValueEx(key,'fDisableCdm')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#				18.9.48.3.3.3 Ensure 'Do not allow LPT port redirection' is set to 'Enabled'
def fDisableLPT():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 0, KEY_READ)
		value = (QueryValueEx(key,'fDisableLPT')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#				18.9.48.3.3.4 Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'
def fDisablePNPRedir():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 0, KEY_READ)
		value = (QueryValueEx(key,'fDisablePNPRedir')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#			18.9.48.3.4 Licensing
#			18.9.48.3.5 Printer Redirection
#			18.9.48.3.6 Profiles
#			18.9.48.3.7 RD Connection Broker
#			18.9.48.3.8 Remote Session Environment
#			18.9.48.3.9 Security
#				18.9.48.3.9.1 Ensure 'Always prompt for password upon connection' is set to 'Enabled'
def fPromptForPassword():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 0, KEY_READ)
		value = (QueryValueEx(key,'fPromptForPassword')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#				18.9.48.3.9.2 Ensure 'Require secure RPC communication' is set to 'Enabled'
def fEncryptRPCTraffic():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 0, KEY_READ)
		value = (QueryValueEx(key,'fEncryptRPCTraffic')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#				18.9.48.3.9.3 Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
def MinEncryptionLevel():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 0, KEY_READ)
		value = (QueryValueEx(key,'MinEncryptionLevel')[0])
	except:
		return "NOT CONFIG"
	if value == 3:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
	
#			18.9.48.3.10 Session Time Limits
#				18.9.48.3.10.1 Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'
def MaxIdleTime():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 0, KEY_READ)
		value = (QueryValueEx(key,'MaxIdleTime')[0])
	except:
		return "NOT CONFIG"
	if value <= 900000:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#				18.9.48.3.10.2 Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'
def MaxDisconnectionTime():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 0, KEY_READ)
		value = (QueryValueEx(key,'MaxDisconnectionTime')[0])
	except:
		return "NOT CONFIG"
	if value == 60000:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
	
#			18.9.48.3.11 Temporary folders
#				18.9.48.3.11.1 Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'	
def DeleteTempDirsOnExit():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 0, KEY_READ)
		value = (QueryValueEx(key,'DeleteTempDirsOnExit')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
	
#				18.9.48.3.11.2 Ensure 'Do not use temporary folders per session' is set to 'Disabled'	
def PerSessionTempDir():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', 0, KEY_READ)
		value = (QueryValueEx(key,'PerSessionTempDir')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#	18.9.49 RSS Feeds
#		18.9.49.1 Ensure 'Prevent downloading of enclosures' is set to 'Enabled'	
def DisableEnclosureDownload():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds', 0, KEY_READ)
		value = (QueryValueEx(key,'DisableEnclosureDownload')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#	18.9.50 Search
#		18.9.50.1 OCR
#		18.9.50.2 Ensure 'Allow indexing of encrypted files' is set to 'Disabled'
def AllowIndexingEncryptedStoresOrItems():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\Windows Search', 0, KEY_READ)
		value = (QueryValueEx(key,'AllowIndexingEncryptedStoresOrItems')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#	18.9.51 Security Center
#	18.9.52 Server for NIS
#	18.9.53 Shutdown Options
#	18.9.54 SkyDrive
#	18.9.55 Smart Card
#	18.9.56 Software Protection Platform
#	18.9.57 Sound Recorder
#	18.9.58 Store
#	18.9.59 Sync your settings
#	18.9.60 Tablet PC
#	18.9.61 Task Scheduler
#	18.9.62 Text Input
#	18.9.63 Windows Calendar
#	18.9.64 Windows Color System
#	18.9.65 Windows Customer Experience Improvement Program
#	18.9.66 Windows Defender
#		18.9.66.1 Client Interface
#		18.9.66.2 Exclusions
#		18.9.66.3 MAPS
#			18.9.66.3.1 Ensure 'Join Microsoft MAPS' is set to 'Disabled'
def SpynetReporting():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows Defender\Spynet', 0, KEY_READ)
		value = (QueryValueEx(key,'SpynetReporting')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#	18.9.67 Windows Error Reporting
#		18.9.67.1 Advanced Error Reporting Settings
#		18.9.67.2 Consent
#			18.9.67.2.1 Ensure 'Configure Default consent' is set to 'Enabled: Always ask before sending data'
def DefaultConsent():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent', 0, KEY_READ)
		value = (QueryValueEx(key,'DefaultConsent')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#	18.9.68 Windows Game Recording and Broadcasting
#	18.9.69 Windows Installer
#		18.9.69.1 Ensure 'Allow user control over installs' is set to 'Disabled'	
def EnableUserControl():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\Installer', 0, KEY_READ)
		value = (QueryValueEx(key,'EnableUserControl')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#		18.9.69.2 Ensure 'Always install with elevated privileges' is set to 'Disabled'
def AlwaysInstallElevated():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\Installer', 0, KEY_READ)
		value = (QueryValueEx(key,'AlwaysInstallElevated')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#		18.9.69.3 Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'	
def SafeForScripting():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\Installer', 0, KEY_READ)
		value = (QueryValueEx(key,'SafeForScripting')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#	18.9.70 Windows Logon Options
#	18.9.71 Windows Mail
#	18.9.72 Windows Media Center
#	18.9.73 Windows Media Digital Rights Management
#	18.9.74 Windows Media Player
#	18.9.75 Windows Meeting Space
#	18.9.76 Windows Messenger
#	18.9.77 Windows Mobility Center
#	18.9.78 Windows Movie Maker
#	18.9.79 Windows PowerShell	--> check ( note : powershellexecutionpolicy.admx/adml windows 10 Administrative Templates)
#		18.9.79.1 Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'
def EnableScriptBlockLogging():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 0, KEY_READ)
		value = (QueryValueEx(key,'EnableScriptBlockLogging')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)
	
#		18.9.79.2 Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'
def EnableTranscripting():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription', 0, KEY_READ)
		value = (QueryValueEx(key,'EnableTranscripting')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#	18.9.80 Windows Reliability Analysis
#	18.9.81 Windows Remote Management (WinRM)
#		18.9.81.1 WinRM Client
#			18.9.81.1.1 Ensure 'Allow Basic authentication' is set to 'Disabled'
def AllowBasic():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\WinRM\Client', 0, KEY_READ)
		value = (QueryValueEx(key,'AllowBasic')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#			18.9.81.1.2 Ensure 'Allow unencrypted traffic' is set to 'Disabled'
def AllowUnencryptedTraffic():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\WinRM\Client', 0, KEY_READ)
		value = (QueryValueEx(key,'AllowUnencryptedTraffic')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#			18.9.81.1.3 Ensure 'Disallow Digest authentication' is set to 'Enabled'
def AllowDigest():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\WinRM\Client', 0, KEY_READ)
		value = (QueryValueEx(key,'AllowDigest')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#		18.9.81.2 WinRM Service
#			18.9.81.2.1 Ensure 'Allow Basic authentication' is set to 'Disabled'
def AllowBasicService():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\WinRM\Service', 0, KEY_READ)
		value = (QueryValueEx(key,'AllowBasic')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#			18.9.81.2.2 Ensure 'Allow unencrypted traffic' is set to 'Disabled'	
def AllowUnencryptedTrafficService():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\WinRM\Service', 0, KEY_READ)
		value = (QueryValueEx(key,'AllowUnencryptedTraffic')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#			18.9.81.2.3 Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'  -> not set for any plug-in  (check)
def DisableRunAs():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\WinRM\Service', 0, KEY_READ)
		value = (QueryValueEx(key,'DisableRunAs')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#	18.9.82 Windows Remote Shell
#		18.9.82.1 Ensure 'Allow Remote Shell Access' is set to 'Disabled'
def AllowRemoteShellAccess():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\WinRM\Service\WinRS', 0, KEY_READ)
		value = (QueryValueEx(key,'AllowRemoteShellAccess')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	else:
		return 'WARNING'
	CloseKey(key)

#	18.9.83 Windows SideShow -> Sideshow.admx/adml included with the Microsoft Windows Vista, 2008, 7/2008R2 & 8/2012 Administrative Templates
#	18.9.84 Windows System Resource Manager -> SystemResourceManager.admx/adml that is included with the Microsoft Windows Vista, 2008, 7/2008R2 & 8/2012 Administrative Templates.
#	18.9.85 Windows Update
#		18.9.85.1 Ensure 'Configure Automatic Updates' is set to 'Enabled'
def NoAutoUpdate():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\WindowsUpdate\AU', 0, KEY_READ)
		value = (QueryValueEx(key,'NoAutoUpdate')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'WARNING'
	CloseKey(key)

#		18.9.85.2 Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'
def ScheduledInstallDay():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\WindowsUpdate\AU', 0, KEY_READ)
		value = (QueryValueEx(key,'ScheduledInstallDay')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'NOT GOOD'
	CloseKey(key)

#		18.9.85.3 Ensure 'Do not adjust default option to 'Install Updates and Shut Down' in Shut Down Windows dialog box' is set to 'Disabled'
def NoAUAsDefaultShutdownOption():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\WindowsUpdate\AU', 0, KEY_READ)
		value = (QueryValueEx(key,'NoAUAsDefaultShutdownOption')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'NOT GOOD'
	CloseKey(key)

#		18.9.85.4 Ensure 'Do not display 'Install Updates and Shut Down' option in Shut Down Windows dialog box' is set to 'Disabled'
def NoAUShutdownOption():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\WindowsUpdate\AU', 0, KEY_READ)
		value = (QueryValueEx(key,'NoAUShutdownOption')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'NOT GOOD'
	CloseKey(key)

#		18.9.85.5 Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'
def NoAutoRebootWithLoggedOnUsers():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\WindowsUpdate\AU', 0, KEY_READ)
		value = (QueryValueEx(key,'NoAutoRebootWithLoggedOnUsers')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'NOT GOOD'
	CloseKey(key)

#		18.9.85.6 Ensure 'Reschedule Automatic Updates scheduled installations' is set to 'Enabled: 1 minute'
def RescheduleWaitTime():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\Windows\WindowsUpdate\AU', 0, KEY_READ)
		value0 = (QueryValueEx(key,'RescheduleWaitTimeEnabled')[0])
		value1 = (QueryValueEx(key,'RescheduleWaitTime')[0])
	except:
		return "NOT CONFIG"
	if value0 == 1 and value1 == 1:
		return 'OK'
	return 'NOT GOOD'
	CloseKey(key)

	
	
	
	
	
	
	
	
	
	




