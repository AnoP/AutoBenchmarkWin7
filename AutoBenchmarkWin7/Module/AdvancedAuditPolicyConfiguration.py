################################ 	17.	Advanced Audit Policy Configuration		#########################################
##########	17.1 Account Logon
import csv
import os
import ctypes
#	17.1.1 Ensure 'Audit Credential Validation' is set to 'Success and Failure'
def AuditCredentialValidation():
	temp = []
	value = []
	f = open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit Credential Validation' in temp:
		locate = value[temp.index('Audit Credential Validation')]
		if locate == 'Success' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success and Failure':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'
##########	17.2 Account Management
#	17.2.1 Ensure 'Audit Application Group Management' is set to 'Success and Failure' 
def AuditApplicationGroupManagement():
	temp = []
	value = []
	f = open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit Application Group Management' in temp:
		locate = value[temp.index('Audit Application Group Management')]
		if locate == 'Success' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success and Failure':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'
#	17.2.2 Ensure 'Audit Computer Account Management' is set to 'Success and Failure'
def AuditComputerAccountManagement():
	temp = []
	value = []
	f = open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit Computer Account Management' in temp:
		locate = value[temp.index('Audit Computer Account Management')]
		if locate == 'Success' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success and Failure':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'
#	17.2.3 Ensure 'Audit Other Account Management Events' is set to 'Success and Failure'
def AuditOtherAccountManagementEvents():
	temp = []
	value = []
	f = open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit Other Account Management Events' in temp:
		locate = value[temp.index('Audit Other Account Management Events')]
		if locate == 'Success' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success and Failure':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'
#	17.2.4 Ensure 'Audit Security Group Management' is set to 'Success and Failure'
def AuditSecurityGroupManagement():
	temp = []
	value = []
	f = open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit Security Group Management' in temp:
		locate = value[temp.index('Audit Security Group Management')]
		if locate == 'Success' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success and Failure':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'
#	17.2.5 Ensure 'Audit User Account Management' is set to 'Success and Failure'
def AuditUserAccountManagement():
	temp = []
	value = []
	f = open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit User Account Management' in temp:
		locate = value[temp.index('Audit User Account Management')]
		if locate == 'Success' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success and Failure':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'
##########	17.3 Detailed Tracking
#	17.3.1 Ensure 'Audit Process Creation' is set to 'Success' (Scored)
def AuditProcessCreation():
	temp = []
	value = []
	f = open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit Process Creation' in temp:
		locate = value[temp.index('Audit Process Creation')]
		if locate == 'Success and Failure' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'
##########	17.4 DS Access
##########	17.5 Logon/Logoff
#	17.5.1 Ensure 'Audit Account Lockout' is set to 'Success' (Scored)
def AuditAccountLockout():
	temp = []
	value = []
	f = open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit Account Lockout' in temp:
		locate = value[temp.index('Audit Account Lockout')]
		if locate == 'Success and Failure' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'
#	17.5.2 Ensure 'Audit Logoff' is set to 'Success' (Scored)
def AuditLogoff():
	temp = []
	value = []
	f = open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit Logoff' in temp:
		locate = value[temp.index('Audit Logoff')]
		if locate == 'Success and Failure' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'
#	17.5.3 Ensure 'Audit Logon' is set to 'Success and Failure' (Scored)
def AuditLogon():
	temp = []
	value = []
	f = open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit Logon' in temp:
		locate = value[temp.index('Audit Logon')]
		if locate == 'Success' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success and Failure':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'
#	17.5.4 Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
def AuditOtherLogonLogoffEvents():
	temp = []
	value = []
	f = open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit Other Logon/Logoff Events' in temp:
		locate = value[temp.index('Audit Other Logon/Logoff Events')]
		if locate == 'Success' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success and Failure':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'
#	17.5.5 Ensure 'Audit Special Logon' is set to 'Success' (Scored)
def AuditSpecialLogon():
	temp = []
	value = []
	f = open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit Special Logon' in temp:
		locate = value[temp.index('Audit Special Logon')]
		if locate == 'Success and Failure' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'
##########	17.6 Object Access
##########	17.7 Policy Change
#	17.7.1 Ensure 'Audit Audit Policy Change' is set to 'Success and Failure'
def AuditAuditPolicyChange():
	temp = []
	value = []
	f = open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit Audit Policy Change' in temp:
		locate = value[temp.index('Audit Audit Policy Change')]
		if locate == 'Success' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success and Failure':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'
#	17.7.2 Ensure 'Audit Authentication Policy Change' is set to 'Success'
def AuditAuthenticationPolicyChange():
	temp = []
	value = []
	f = open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit Authentication Policy Change' in temp:
		locate = value[temp.index('Audit Authentication Policy Change')]
		if locate == 'Success' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success and Failure':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'
###########	17.8 Privilege Use
#	17.8.1 Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'
def AuditSensitivePrivilegeUse():
	temp = []
	value = []
	f = open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit Sensitive Privilege Use' in temp:
		locate = value[temp.index('Audit Sensitive Privilege Use')]
		if locate == 'Success' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success and Failure':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'
##########	17.9 System
#	17.9.1 Ensure 'Audit IPsec Driver' is set to 'Success and Failure'
def AuditIPsecDriver():
	temp = []
	value = []
	f = open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit IPsec Driver' in temp:
		locate = value[temp.index('Audit IPsec Driver')]
		if locate == 'Success' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success and Failure':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'
#	17.9.2 Ensure 'Audit Other System Events' is set to 'Success and Failure'
def AuditOtherSystemEvents():
	temp = []
	value = []
	f= open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit Other System Events' in temp:
		locate = value[temp.index('Audit Other System Events')]
		if locate == 'Success' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success and Failure':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'
#	17.9.3 Ensure 'Audit Security State Change' is set to 'Success'
def AuditSecurityStateChange():
	temp = []
	value = []
	f= open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit Security State Change' in temp:
		locate = value[temp.index('Audit Security State Change')]
		if locate == 'Success and Failure' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'
#	17.9.4 Ensure 'Audit Security System Extension' is set to 'Success and Failure'
def AuditSecuritySystemExtension():
	temp = []
	value = []
	f= open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit Security System Extension' in temp:
		locate = value[temp.index('Audit Security System Extension')]
		if locate == 'Success' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success and Failure':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'
#	17.9.5 Ensure 'Audit System Integrity' is set to 'Success and Failure'
def AuditSystemIntegrity():
	temp = []
	value = []
	f= open('Data\\audit.csv','rt')
	reader = csv.reader(f)
	for row in reader:
		temp.append(row[2])
		value.append(row[4])
	if 'Audit System Integrity' in temp:
		locate = value[temp.index('Audit System Integrity')]
		if locate == 'Success' or locate == 'Failure' or locate == 'No Auditing':
			return 'NOT GOOD'
		if locate == 'Success and Failure':
			return 'OK'
		return 'WARNING'
	return 'NOT CONFIG'