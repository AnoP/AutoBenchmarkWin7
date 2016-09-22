from _winreg import *
################################ 	9.	Windows Firewall With Advanced Security		#########################################
############################################	Public Profile ##############################################################
#   9.3.1	Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)

def Firewallstate():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PublicProfile', 0, KEY_READ)
		value = (QueryValueEx(key,'EnableFirewall')[0])
	except:
		return "NOT FOUND"
	if value == 1 :
		return 'OK'
	else:
			return 'WARNING';
	CloseKey(key)
	
#	9.3.2	Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'
def Inboundconnections():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PublicProfile', 0, KEY_READ)
		value = (QueryValueEx(key,'DefaultInboundAction')[0])
	except:
		return "NOT FOUND"
	if value == 1 :
		return 'OK'
	else:
		return 'WARNING';
	CloseKey(key)

#	9.3.3	Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'	
def Outboundconnections():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PublicProfile', 0, KEY_READ)
		value = (QueryValueEx(key,'DefaultOutboundAction')[0])
	except:
		return "NOT FOUND"
	if value == 0 :
		return 'OK'
	else:
		return 'WARNING';
	CloseKey(key)

#	9.3.4	Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'
def Displayanotification():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PublicProfile', 0, KEY_READ)
		value = (QueryValueEx(key,'DisableNotifications')[0])
	except:
		return "NOT FOUND"
	if value == 1 :
		return 'OK'
	else:
		return 'WARNING';
	CloseKey(key)

#	9.3.5	Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'Yes (default)'
def Applylocalfirewallrules():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PublicProfile', 0, KEY_READ)
		value = (QueryValueEx(key,'AllowLocalPolicyMerge')[0])
	except:
		return "NOT FOUND"
	if value == 1 :
		return 'OK'
	else:
		return 'WARNING';
	CloseKey(key)

#	9.3.6	Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'Yes (default)'
def Applylocalconnectionsecurityrules():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PublicProfile', 0, KEY_READ)
		value = (QueryValueEx(key,'AllowLocalIPsecPolicyMerge')[0])
	except:
		return "NOT FOUND"
	if value == 1 :
		return 'OK'
	else:
		return 'WARNING';
	CloseKey(key)

#	9.3.7	Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log'
def LoggingCustomizeName():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging', 0, KEY_READ)
		value = (QueryValueEx(key,'LogFilePath'))[0]
	except:
		return "OK"
	temp = "%systemroot%\system32\logfiles\\firewall\publicfw.log"
	if (value == temp )== 1:
		return 'GOOD'
	else:
		return 'WARNING'
	CloseKey(key)

#	9.3.8	Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'	
def LoggingCustomizeSize():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging', 0, KEY_READ)
		value = (QueryValueEx(key,'LogFileSize')[0])
	except:
		return "OK"
	if value >= 16384 :
		return 'GOOD'
	else:
		return 'WARNING';
	CloseKey(key)

#	9.3.9	Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'
def Logdroppedpackets():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging', 0, KEY_READ)
		value = (QueryValueEx(key,'LogDroppedPackets')[0])
	except:
		return "OK"
	if value == 1 :
		return 'GOOD'
	else:
		return 'WARNING';
	CloseKey(key)

#	9.1.10	Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'
def LogSuccessfulConnections():
	try: 
		key = OpenKey(HKEY_LOCAL_MACHINE, r'Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging', 0, KEY_READ)
		value = (QueryValueEx(key,'LogSuccessfulConnections')[0])
	except:
		return "OK"
	if value == 1 :
		return 'GOOD'
	else:
		return 'WARNING';
	CloseKey(key)








