from _winreg import *
################################ 	9.	Windows Firewall With Advanced Security		#########################################
############################################	Private Profile ##############################################################
#   9.2.1	Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)

def Firewallstate():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PrivateProfile', 0, KEY_READ)
		value = (QueryValueEx(key,'EnableFirewall')[0])
	except:
		return "NOT FOUND"
	if value == 1 :
		return 'OK'
	else:
			return 'WARNING';
	CloseKey(key)
	
#	9.2.2	Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'
def Inboundconnections():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PrivateProfile', 0, KEY_READ)
		value = (QueryValueEx(key,'DefaultInboundAction')[0])
	except:
		return "NOT FOUND"
	if value == 1 :
		return 'OK'
	else:
		return 'WARNING';
	CloseKey(key)

#	9.2.3	Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'	
def Outboundconnections():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PrivateProfile', 0, KEY_READ)
		value = (QueryValueEx(key,'DefaultOutboundAction')[0])
	except:
		return "NOT FOUND"
	if value == 0 :
		return 'OK'
	else:
		return 'WARNING';
	CloseKey(key)

#	9.2.4	Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'
def Displayanotification():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PrivateProfile', 0, KEY_READ)
		value = (QueryValueEx(key,'DisableNotifications')[0])
	except:
		return "NOT FOUND"
	if value == 1 :
		return 'OK'
	else:
		return 'WARNING';
	CloseKey(key)

#	9.1.5	Ensure 'Windows Firewall: Private: Settings: Apply local firewall rules' is set to 'Yes (default)'
def Applylocalfirewallrules():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PrivateProfile', 0, KEY_READ)
		value = (QueryValueEx(key,'AllowLocalPolicyMerge')[0])
	except:
		return "NOT FOUND"
	if value == 1 :
		return 'OK'
	else:
		return 'WARNING';
	CloseKey(key)

#	9.1.6	Ensure 'Windows Firewall: Private: Settings: Apply local connection security rules' is set to 'Yes (default)'
def Applylocalconnectionsecurityrules():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PrivateProfile', 0, KEY_READ)
		value = (QueryValueEx(key,'AllowLocalIPsecPolicyMerge')[0])
	except:
		return "NOT FOUND"
	if value == 1 :
		return 'OK'
	else:
		return 'WARNING';
	CloseKey(key)

#	9.1.7	Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'
def LoggingCustomizeName():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging', 0, KEY_READ)
		value = (QueryValueEx(key,'LogFilePath'))[0]
	except:
		return "OK"
	temp = "%systemroot%\system32\logfiles\\firewall\privatefw.log"
	if (value == temp )== 1:
		return 'GOOD'
	else:
		return 'WARNING'
	CloseKey(key)

#	9.1.8	Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'	
def LoggingCustomizeSize():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging', 0, KEY_READ)
		value = (QueryValueEx(key,'LogFileSize')[0])
	except:
		return "OK"
	if value >= 16384 :
		return 'GOOD'
	else:
		return 'WARNING';
	CloseKey(key)

#	9.1.9	Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'
def Logdroppedpackets():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging', 0, KEY_READ)
		value = (QueryValueEx(key,'LogDroppedPackets')[0])
	except:
		return "OK"
	if value == 1 :
		return 'GOOD'
	else:
		return 'WARNING';
	CloseKey(key)

#	9.1.10	Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'
def LogSuccessfulConnections():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging', 0, KEY_READ)
		value = (QueryValueEx(key,'LogSuccessfulConnections')[0])
	except:
		return "OK"
	if value == 1 :
		return 'GOOD'
	else:
		return 'WARNING';
	CloseKey(key)








