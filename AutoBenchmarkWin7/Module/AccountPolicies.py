####################	1. Account Policies	########################
import os
import codecs
f = codecs.open('Data\sercurityoptions.txt','rb','utf-16')
temp = f.read()


##########	1.1 Password Policy
#	1.1.1  Ensure 'Enforce password history' is set to '24 or more password(s)' 
def PasswordHistorySize():
	if u'PasswordHistorySize = 24\r\n' in temp:
		return 'OK'
	return 'WARNING'
#	1.1.2 Ensure 'Maximum password age' is set to '60 or fewer days, but not 0' 
def MaximumPasswordAge():
	t = u'MaximumPasswordAge = %s\r\n'
	if t%42 in temp:
		return 'NOT GOOD'
	for i in range(1,61):
		if t%i in temp:
			return 'OK'
	return 'WARNING'
#	1.1.3 Ensure 'Minimum password age' is set to '1 or more day(s)'
def MinimumPasswordAge():
	t = u'MinimumPasswordAge = %s\r\n'
	if t%0 in temp:
		return 'NOT GOOD'
	for i in range(1,999):
		if t%i in temp:
			return 'OK'
	return 'WARNING'
#	1.1.4 Ensure 'Minimum password length' is set to '14 or more character(s)'
def MinimumPasswordLength():
	t = u'MinimumPasswordLength = %s\r\n'
	if t%0 in temp:
		return 'NOT GOOD'
	if t%14 in temp:
		return 'OK'
	return 'WARNING'
#	1.1.5 Ensure 'Password must meet complexity requirements' is set to 'Enabled' 
def PasswordComplexity():
	t = u'PasswordComplexity = %s\r\n'
	if t%0 in temp:
		return 'NOT GOOD'
	if t%1 in temp:
		return 'OK'
	return 'WARNING'
#	1.1.6 Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
def ClearTextPassword():
	t = u'ClearTextPassword = %s\r\n'
	if t%0 in temp:
		return 'OK'
	return 'WARNING'
##########	1.2 Account Lockout Policy
#	1.2.1 Ensure 'Account lockout duration' is set to '15 or more minute(s)' -> check
def LockoutDuration():
	t = u'LockoutDuration = %s\r\n'
	for i in range(15,99999):
		if t%i in temp:
			return 'OK'
	if u'LockoutDuration' in temp:
		return 'NOT GOOD'
	return 'WARNING'
#	1.2.2 Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'
def LockoutBadCount():
	t = u'LockoutBadCount = %s\r\n'
	if t%0 in temp:
		return 'NOT GOOD'
	for i in range(1,11):
		if t%i in temp:
			return 'OK'
	return 'WARNING'
#	1.2.3 Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)' 
def ResetLockoutCount():
	t = u'ResetLockoutCount = %s\r\n'
	if t%0 in temp:
		return 'NOT GOOD'
	for i in range(15,99999):
		if t%i in temp:
			return 'OK'
	return 'WARNING'