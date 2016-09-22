################################ 	19.	Administrative Templates ( User)		#########################################
from _winreg import *
import getpass
import os
import string
def get_user_sid():
	username = "%s"%getpass.getuser()
	b = "wmic useraccount where name='%s' get sid"%username
	sid= os.popen(b).read()
	return sid.split()[1]
##########	19.1 Control Panel
#	19.1.1 Add or Remove Programs
#	19.1.2 Display
#	19.1.3 Personalization
#		19.1.3.1 Ensure 'Enable screen saver' is set to 'Enabled'
def ScreenSaveActive():
	try: 
		key = OpenKey(HKEY_USERS, r'%s\Software\Policies\Microsoft\Windows\Control Panel\Desktop'%get_user_sid(), 0, KEY_ALL_ACCESS)
		value = int(QueryValueEx(key,'ScreenSaveActive')[0])
	except:
		return "NOT CONFIG"
	if value == 1 :
		return 'OK'
	return 'NOT GOOD';
	CloseKey(key)
	
#		19.1.3.2 Ensure 'Force specific screen saver: Screen saver executable name' is set to 'Enabled: scrnsave.scr'	
def SCRNSAVE():
	try: 
		key = OpenKey(HKEY_USERS, r'%s\Software\Policies\Microsoft\Windows\Control Panel\Desktop'%get_user_sid(), 0, KEY_ALL_ACCESS)
		value = (QueryValueEx(key,'SCRNSAVE.EXE')[0])
	except:
		return "NOT CONFIG"
	temp = 'scrnsave.scr'
	if (value == temp) == 1 :
		return 'OK'
	return 'NOT GOOD';
	CloseKey(key)
	
#		19.1.3.3 Ensure 'Password protect the screen saver' is set to 'Enabled'
def ScreenSaverIsSecure():
	try: 
		key = OpenKey(HKEY_USERS, r'%s\Software\Policies\Microsoft\Windows\Control Panel\Desktop'%get_user_sid(), 0, KEY_ALL_ACCESS)
		value = int(QueryValueEx(key,'ScreenSaverIsSecure')[0])
	except:
		return "NOT CONFIG"
	if value == 1 :
		return 'OK'
	return 'NOT GOOD';
	CloseKey(key)
	
#		19.1.3.4 Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'
def ScreenSaveTimeOut():
	try: 
		key = OpenKey(HKEY_USERS, r'%s\Software\Policies\Microsoft\Windows\Control Panel\Desktop'%get_user_sid(), 0, KEY_ALL_ACCESS)
		value = int(QueryValueEx(key,'ScreenSaveTimeOut')[0])
	except:
		return "NOT CONFIG"
	if value <= 900 and value > 0 :
		return 'OK'
	elif value == 0:
		return "WARNING"
	return 'NOT GOOD';
	CloseKey(key)
	
##########	19.2 Desktop
##########	19.3 Network
##########	19.4 Shared Folders
##########	19.5 Start Menu and Taskbar
##########	19.6 System
#	19.6.1 Ctrl+Alt+Del Options
#	19.6.2 Driver Installation
#	19.6.3 Folder Redirection
#	19.6.4 Group Policy
#	19.6.5 Internet Communication Management
#	19.6.5.1 Internet Communication settings
#		19.6.5.1.1 Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'
def NoImplicitFeedback():
	try: 
		key = OpenKey(HKEY_USERS, r'%s\Software\Policies\Microsoft\Assistance\Client\1.0'%get_user_sid(), 0, KEY_ALL_ACCESS)
		value = (QueryValueEx(key,'NoImplicitFeedback')[0])
	except:
		return "NOT CONFIG"
	if value == 1 :
		return 'OK'
	return 'NOT GOOD';
	CloseKey(key)
	
##########	19.7 Windows Components
#	19.7.1 Add features to Windows 8 / 8.1 / 10 --> WindowsAnytimeUpgrade.admx/adml that is included with the Microsoft Windows 8/2012, 8.1/2012R2 and Windows 10 Administrative Templates.
#	19.7.2 App runtime
#	19.7.3 Application Compatibility
#	19.7.4 Attachment Manager
#		19.7.4.1 Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'		
def SaveZoneInformation():
	try: 
		key = OpenKey(HKEY_USERS, r'%s\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'%get_user_sid(), 0, KEY_ALL_ACCESS)
		value = (QueryValueEx(key,'SaveZoneInformation')[0])
	except:
		return "NOT CONFIG"
	if value == 2:
		return 'OK'
	return 'NOT GOOD';
	CloseKey(key)

#		19.7.4.2 Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'
def ScanWithAntiVirus():
	try: 
		key = OpenKey(HKEY_USERS, r'%s\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'%get_user_sid(), 0, KEY_ALL_ACCESS)
		value = (QueryValueEx(key,'ScanWithAntiVirus')[0])
	except:
		return "NOT CONFIG"
	if value == 3:
		return 'OK'
	return 'NOT GOOD';
	CloseKey(key)

#	19.7.5 AutoPlay Policies
#	19.7.6 Backup --> WindowsBackup.admx/adml that is included with the Microsoft Windows Vista, 2008, 7/2008R2, 8/2012 and 8.1/2012R2 Administrative Templates
#					  or UserDataBackup.admx/adml included with the Microsoft Windows 10 Administrative Templates.
#	19.7.7 Credential User Interface
#	19.7.8 Desktop Gadgets
#	19.7.9 Desktop Window Manager
#	19.7.10 Digital Locker
#	19.7.11 Edge UI
#	19.7.12 EMET	--> EMET.admx/adml that is included with Microsoft Enhanced Mitigation Experience Toolkit (EMET)
#	19.7.13 File Explorer
#	19.7.14 File Revocation
#	19.7.15 IME
#	19.7.16 Import Video --> CaptureWizard.admx/adml that is included with the Microsoft Windows Vista & 2008 Administrative Templates
#	19.7.17 Instant Search
#	19.7.18 Internet Explorer
#	19.7.19 Location and Sensors
#	19.7.20 Microsoft Edge --> microsoftedge.admx/adml that is included with the Microsoft Windows 10 Administrative Templates
#	19.7.21 Microsoft Management Console
#	19.7.22 Microsoft Passport for Work	--> passport.admx/adml that is included with the Microsoft Windows 10 Administrative Templates
#	19.7.23 NetMeeting
#	19.7.24 Network Projector
#	19.7.25 Network Sharing
#		19.7.25.1 Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'
def NoInplaceSharing():
	try: 
		key = OpenKey(HKEY_USERS, r'%s\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'%get_user_sid(), 0, KEY_ALL_ACCESS)
		value = (QueryValueEx(key,'NoInplaceSharing')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'NOT GOOD';
	CloseKey(key)

#	19.7.26 Presentation Settings
#	19.7.27 Remote Desktop Services
#	19.7.28 RSS Feeds
#	19.7.29 Search --> Search.admx/adml that is included with the Microsoft Windows Vista, 2008, 7/2008R2, 8/2012, 8.1/2012R2 and Windows 10 Administrative Templates
#	19.7.30 Sound Recorder
#	19.7.31 Store --> WinStoreUI.admx/adml that is included with the Microsoft Windows 8/2012 & 8.1/2012R2 Administrative Templates.
#	19.7.32 Tablet PC
#	19.7.33 Task Scheduler
#	19.7.34 Windows Calendar
#	19.7.35 Windows Color System
#	19.7.36 Windows Error Reporting
#	19.7.37 Windows Installer
#		19.7.37.1 Ensure 'Always install with elevated privileges' is set to 'Disabled'
def AlwaysInstallElevated():
	try: 
		key = OpenKey(HKEY_USERS, r'%s\Software\Policies\Microsoft\Windows\Installer'%get_user_sid(), 0, KEY_ALL_ACCESS)
		value = (QueryValueEx(key,'AlwaysInstallElevated')[0])
	except:
		return "NOT CONFIG"
	if value == 0:
		return 'OK'
	return 'NOT GOOD';
	CloseKey(key)

#	19.7.38 Windows Logon Options
#	19.7.39 Windows Mail
#	19.7.40 Windows Media Center
#	19.7.41 Windows Media Player
#	19.7.41.1 Networking
#	19.7.41.2 Playback
#		19.7.41.2.1 Ensure 'Prevent Codec Download' is set to 'Enabled'
def PreventCodecDownload():
	try: 
		key = OpenKey(HKEY_USERS, r'%s\Software\Policies\Microsoft\WindowsMediaPlayer'%get_user_sid(), 0, KEY_ALL_ACCESS)
		value = (QueryValueEx(key,'PreventCodecDownload')[0])
	except:
		return "NOT CONFIG"
	if value == 1:
		return 'OK'
	return 'NOT GOOD';
	CloseKey(key)
	
