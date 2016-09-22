import LocalPolicies
import AccountPolicies
import AdministrativeTemplatesComputer
import AdministrativeTemplatesUser
import AdvancedAuditPolicyConfiguration
import FirewallDomainProfile
import FirewallPrivateProfile
import FirewallPublicProfile
def warning():
	warning = 0
	if (AccountPolicies.PasswordHistorySize() == 'WARNING') ==1 : warning +=1
	if (AccountPolicies.MaximumPasswordAge() == 'WARNING') ==1 : warning +=1
	if (AccountPolicies.MinimumPasswordAge() == 'WARNING') ==1 : warning +=1
	if (AccountPolicies.MinimumPasswordLength() == 'WARNING') ==1 : warning +=1
	if (AccountPolicies.PasswordComplexity() == 'WARNING') ==1 : warning +=1
	if (AccountPolicies.ClearTextPassword() == 'WARNING') ==1 : warning +=1
	if (AccountPolicies.LockoutDuration() == 'WARNING') ==1 : warning +=1
	if (AccountPolicies.LockoutBadCount() == 'WARNING') ==1 : warning +=1
	if (AccountPolicies.ResetLockoutCount() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeTrustedCredManAccessPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeNetworkLogonRight() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeTcbPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeIncreaseQuotaPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeInteractiveLogonRight() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeRemoteInteractiveLogonRight() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeBackupPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeSystemtimePrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeTimeZonePrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeCreatePagefilePrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeCreateTokenPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeCreateGlobalPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeIncreaseBasePriorityPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeCreatePermanentPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeCreateSymbolicLinkPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeDebugPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeDenyNetworkLogonRight() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeDenyBatchLogonRight() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeDenyServiceLogonRight() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeDenyInteractiveLogonRight() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeDenyRemoteInteractiveLogonRight() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeEnableDelegationPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeRemoteShutdownPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeAuditPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeImpersonatePrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeLoadDriverPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeLockMemoryPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeBatchLogonRight() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeServiceLogonRight() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeSecurityPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeRelabelPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeSystemEnvironmentPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeManageVolumePrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeSystemProfilePrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeProfileSingleProcessPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeAssignPrimaryTokenPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeRestorePrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeShutdownPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SeTakeOwnershipPrivilege() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.EnableAdminAccount() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.EnableGuestAccount() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.LimitBlankPasswordUse() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.NewAdministratorName() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.NewGuestName() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SCENoApplyLegacyAuditPolicy() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.crashonauditfail() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.AllocateDASD() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.AddPrinterDriver() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.RequireSignOrSeal() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SealSecureChannel() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SignSecureChannel() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.DisablePasswordChange() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.MaximumPasswordAge() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.RequireStrongKey() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.DontDisplayLastUserName() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.DisableCAD() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.LegalNoticeText() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.LegalNoticeCaption() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.CachedLogonsCount() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.PasswordExpiryWARNING() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.ScRemoveOption() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.RequireSecuritySignature() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.EnableSecuritySignature() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.EnablePlainTextPassword() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.autodisconnect() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.RequireSecuritySignatureServer() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.EnableSecuritySignatureServer() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.enableforcedlogoff() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SMBServerNameHardeningLevel() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.LSAAnonymousNameLookup() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.RestrictAnonymousSAM() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.RestrictAnonymous() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.disabledomaincreds() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.EveryoneIncludesAnonymous() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.NullSessionPipes() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.AllowedExactPaths() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.AllowedPaths() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.restrictnullsessaccess() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.NullSessionShares() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.ForceGuest() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.UseMachineId() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.allownullsessionfallback() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.AllowOnlineID() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.SupportedEncryptionTypes() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.NoLMHash() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.enableforcedlogoff1() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.LmCompatibilityLevel() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.LDAPClientIntegrity() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.NTLMMinClientSec() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.NTLMMinServerSec() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.ForceKeyProtection() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.ObCaseInsensitive() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.ProtectionMode() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.Optional() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.FilterAdministratorToken() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.EnableUIADesktopToggle() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.ConsentPromptBehaviorAdmin() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.ConsentPromptBehaviorUser() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.EnableInstallerDetection() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.EnableSecureUIAPaths() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.EnableLUA() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.PromptOnSecureDesktop() == 'WARNING') ==1 : warning +=1
	if (LocalPolicies.EnableVirtualization() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NCStdDomainUserSetLocation() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.SafeDllSearchMode() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.AllowBasic() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NtpServer() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.AllowIndexingEncryptedStoresOrItems() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.ExitOnMSICW() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.Nonamereleaseondemand() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NoBackgroundPolicy() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.fAllowUnsolicited() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.LocalAccountTokenFilterPolicy() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.Retention3() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.EnableUserControl() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.RDVPassphrase() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NoHeapTerminationOnCorruption() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.TurnonResponder() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.ScreenSaverGracePeriod() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.SafeForScripting() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DisablePasswordReveal() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NoPublishingWizard() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.RDVDiscoveryVolumeType() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.PasswordLength() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.RDVRecovery() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.MaxDisconnectionTime() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DisableQueryRemoteServer() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NoWebServices() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.ACSettingIndex1() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.TurnonMapperIO() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.fDisableLPT() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.MaxSize3() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.MaxSize2() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.MaxSize1() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.SpynetReporting() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.AllowRemoteRPC() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.UseLogonCredential() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.FDVAllowUserCert() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NoInternetOpenWith() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.PreventHandwritingDataSharing() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DisableIPSourceRouting() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.ScenarioExecutionEnabled() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DisableWebPnPDownload() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.EnableAuthEpResolution() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.EnableScriptBlockLogging() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DCSettingIndex1() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NoOnlinePrintsWizard() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.FDVRecoveryKey() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.EncryptionMethod() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.UseTPMPIN() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.AutoAdminLogon() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.EnableBDEWithNoTPM() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.RestrictRemoteClients() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.EMETInstall() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.SysSettings() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DeleteTempDirsOnExit() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.Peernet() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.Registrars() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.AllowDigest() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.OSRequireActiveDirectoryBackup() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.TurnOffSidebar() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NoAUAsDefaultShutdownOption() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NoDriveTypeAutoRun() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NoRegistration() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.OSManageDRA() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.AllowUnencryptedTraffic() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.PreventHandwritingErrorReports() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.FDVHideRecoveryPage() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.Defaults1() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NoAutoUpdate() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.UseAdvancedStartup() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.FDVDiscoveryVolumeType() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.UseTPMKeyPIN() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.FDVRecovery() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.FDVPassphrase() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.ASLR() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.EnumerateAdministrators() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DisableBkGndGroupPolicy() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.RDVEnforceUserCert() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.RDVActiveDirectoryBackup() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.RDVActiveDirectoryInfoToStore() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.Tcpmaxdataretransmissions() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.RDVRecoveryKey() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.PerSessionTempDir() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NoAUShutdownOption() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.Defaults() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DisableHTTPPrinting() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DenyDeviceClasses() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.AlwaysInstallElevated() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DisablePasswordSaving() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.WindowsErrorReporting() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.fPromptForPassword() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DisableIP6SourceRouting() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.CEIP() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NCAllowNetBridgeNLA() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.PreXPSP2ShellProtocolBehavior() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.AdmPwd() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.CEIPEnable() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DisableWcnUi() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.Tcpmaxdataretransmissions6() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.PwdExpirationProtection() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.FDVManageDRA() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.OSActiveDirectoryInfoToStore() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.PasswordAgeDays() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DEP() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NoAutorun() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.FDVRecoveryPassword() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.OSHideRecoveryPage() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NoAutoRebootWithLoggedOnUsers() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.TurnOffUserInstalledGadgets() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.EnableICMPRedirect() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DisableLocation() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.OSActiveDirectoryBackup() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.Retention1() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.Retention2() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.RDVManageDRA() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DCSettingIndex() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.UseTPMKey() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.PasswordComplexity() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DenyDeviceClasses1() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.AdmPwdEnabled() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.LogonType() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.RescheduleWaitTime() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.AllowUnencryptedTrafficService() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.UseTPM() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.EnableTranscripting() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.ACSettingIndex() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.RDVRecoveryPassword() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.FDVEnforceUserCert() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.UseEnhancedPin() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.AllowBasicService() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DenyDeviceClassesRetroactive() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NoGPOListChanges() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.fDisableCcm() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.RDVDenyWriteAccess() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DisableContentFileUpdates() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.MinEncryptionLevel() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.RDVDenyCrossOrg() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.OSRecoveryPassword() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.FDVRequireActiveDirectoryBackup() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.fDisablePNPRedir() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.OSRecoveryKey() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.ProcessCreationIncludeCmdLineEnabled() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.MaxSize() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.PerformRouterDiscovery() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DisableHomeGroup() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.RDVHideRecoveryPage() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NoDataExecutionPrevention() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.HardenedPaths() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.FDVActiveDirectoryBackup() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.MinimumPIN() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.RDVRequireActiveDirectoryBackup() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.fDenyTSConnections() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.fAllowToGetHelp() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.Disablesavepassword() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.MaxIdleTime() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.AllowRemoteShellAccess() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DisabledComponents() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NoAutoplayfornonVolume() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.WARNINGLevel() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.fDisableCdm() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.IE() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DisableRunAs() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.SEHOP() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.NtpClient() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.RDVAllowUserCert() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.KeepAliveTime() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.OSRecovery() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DefaultConsent() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.DisableEnclosureDownload() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.ScheduledInstallDay() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.FDVActiveDirectoryInfoToStore() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.fEncryptRPCTraffic() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesComputer.Retention() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesUser.NoImplicitFeedback() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesUser.ScreenSaveTimeOut() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesUser.ScreenSaverIsSecure() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesUser.ScanWithAntiVirus() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesUser.SaveZoneInformation() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesUser.AlwaysInstallElevated() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesUser.SCRNSAVE() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesUser.NoInplaceSharing() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesUser.PreventCodecDownload() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesUser.ScreenSaveActive() == 'WARNING') ==1 : warning +=1
	if (AdministrativeTemplatesUser.get_user_sid() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditApplicationGroupManagement() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditSecuritySystemExtension() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditCredentialValidation() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditSensitivePrivilegeUse() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditAuthenticationPolicyChange() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditLogon() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditLogoff() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditProcessCreation() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditOtherSystemEvents() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditSystemIntegrity() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditAccountLockout() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditSpecialLogon() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditOtherLogonLogoffEvents() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditAuditPolicyChange() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditComputerAccountManagement() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditOtherAccountManagementEvents() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditSecurityStateChange() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditSecurityGroupManagement() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditIPsecDriver() == 'WARNING') ==1 : warning +=1
	if (AdvancedAuditPolicyConfiguration.AuditUserAccountManagement() == 'WARNING') ==1 : warning +=1
	if (FirewallDomainProfile.Applylocalconnectionsecurityrules() == 'WARNING') ==1 : warning +=1
	if (FirewallDomainProfile.Firewallstate() == 'WARNING') ==1 : warning +=1
	if (FirewallDomainProfile.Displayanotification() == 'WARNING') ==1 : warning +=1
	if (FirewallDomainProfile.Applylocalfirewallrules() == 'WARNING') ==1 : warning +=1
	if (FirewallDomainProfile.Inboundconnections() == 'WARNING') ==1 : warning +=1
	if (FirewallDomainProfile.LogSuccessfulConnections() == 'WARNING') ==1 : warning +=1
	if (FirewallDomainProfile.LoggingCustomizeSize() == 'WARNING') ==1 : warning +=1
	if (FirewallDomainProfile.LoggingCustomizeName() == 'WARNING') ==1 : warning +=1
	if (FirewallDomainProfile.Logdroppedpackets() == 'WARNING') ==1 : warning +=1
	if (FirewallDomainProfile.Outboundconnections() == 'WARNING') ==1 : warning +=1
	if (FirewallPrivateProfile.Applylocalconnectionsecurityrules() == 'WARNING') ==1 : warning +=1
	if (FirewallPrivateProfile.Firewallstate() == 'WARNING') ==1 : warning +=1
	if (FirewallPrivateProfile.Displayanotification() == 'WARNING') ==1 : warning +=1
	if (FirewallPrivateProfile.Applylocalfirewallrules() == 'WARNING') ==1 : warning +=1
	if (FirewallPrivateProfile.Inboundconnections() == 'WARNING') ==1 : warning +=1
	if (FirewallPrivateProfile.LogSuccessfulConnections() == 'WARNING') ==1 : warning +=1
	if (FirewallPrivateProfile.LoggingCustomizeSize() == 'WARNING') ==1 : warning +=1
	if (FirewallPrivateProfile.LoggingCustomizeName() == 'WARNING') ==1 : warning +=1
	if (FirewallPrivateProfile.Logdroppedpackets() == 'WARNING') ==1 : warning +=1
	if (FirewallPrivateProfile.Outboundconnections() == 'WARNING') ==1 : warning +=1
	if (FirewallPublicProfile.Applylocalconnectionsecurityrules() == 'WARNING') ==1 : warning +=1
	if (FirewallPublicProfile.Firewallstate() == 'WARNING') ==1 : warning +=1
	if (FirewallPublicProfile.Displayanotification() == 'WARNING') ==1 : warning +=1
	if (FirewallPublicProfile.Applylocalfirewallrules() == 'WARNING') ==1 : warning +=1
	if (FirewallPublicProfile.Inboundconnections() == 'WARNING') ==1 : warning +=1
	if (FirewallPublicProfile.LogSuccessfulConnections() == 'WARNING') ==1 : warning +=1
	if (FirewallPublicProfile.LoggingCustomizeSize() == 'WARNING') ==1 : warning +=1
	if (FirewallPublicProfile.LoggingCustomizeName() == 'WARNING') ==1 : warning +=1
	if (FirewallPublicProfile.Logdroppedpackets() == 'WARNING') ==1 : warning +=1
	if (FirewallPublicProfile.Outboundconnections() == 'WARNING') ==1 : warning +=1
	return warning
def notconfig():
	notconfig = 0
	if (AccountPolicies.PasswordHistorySize() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AccountPolicies.MaximumPasswordAge() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AccountPolicies.MinimumPasswordAge() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AccountPolicies.MinimumPasswordLength() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AccountPolicies.PasswordComplexity() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AccountPolicies.ClearTextPassword() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AccountPolicies.LockoutDuration() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AccountPolicies.LockoutBadCount() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AccountPolicies.ResetLockoutCount() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeTrustedCredManAccessPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeNetworkLogonRight() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeTcbPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeIncreaseQuotaPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeInteractiveLogonRight() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeRemoteInteractiveLogonRight() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeBackupPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeSystemtimePrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeTimeZonePrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeCreatePagefilePrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeCreateTokenPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeCreateGlobalPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeCreatePermanentPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeCreateSymbolicLinkPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeDebugPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeIncreaseBasePriorityPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeDenyNetworkLogonRight() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeDenyBatchLogonRight() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeDenyServiceLogonRight() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeDenyInteractiveLogonRight() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeDenyRemoteInteractiveLogonRight() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeEnableDelegationPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeRemoteShutdownPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeAuditPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeImpersonatePrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeLoadDriverPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeLockMemoryPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeBatchLogonRight() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeServiceLogonRight() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeSecurityPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeRelabelPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeSystemEnvironmentPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeManageVolumePrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeSystemProfilePrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeProfileSingleProcessPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeAssignPrimaryTokenPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeRestorePrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeShutdownPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SeTakeOwnershipPrivilege() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.EnableAdminAccount() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.EnableGuestAccount() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.LimitBlankPasswordUse() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.NewAdministratorName() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.NewGuestName() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SCENoApplyLegacyAuditPolicy() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.crashonauditfail() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.AllocateDASD() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.AddPrinterDriver() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.RequireSignOrSeal() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SealSecureChannel() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SignSecureChannel() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.DisablePasswordChange() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.MaximumPasswordAge() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.RequireStrongKey() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.DontDisplayLastUserName() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.DisableCAD() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.LegalNoticeText() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.LegalNoticeCaption() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.CachedLogonsCount() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.PasswordExpiryWARNING() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.ScRemoveOption() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.RequireSecuritySignature() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.EnableSecuritySignature() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.EnablePlainTextPassword() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.autodisconnect() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.RequireSecuritySignatureServer() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.EnableSecuritySignatureServer() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.enableforcedlogoff() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SMBServerNameHardeningLevel() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.LSAAnonymousNameLookup() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.RestrictAnonymousSAM() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.RestrictAnonymous() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.disabledomaincreds() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.EveryoneIncludesAnonymous() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.NullSessionPipes() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.AllowedExactPaths() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.AllowedPaths() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.restrictnullsessaccess() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.NullSessionShares() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.ForceGuest() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.UseMachineId() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.allownullsessionfallback() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.AllowOnlineID() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.SupportedEncryptionTypes() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.NoLMHash() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.enableforcedlogoff1() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.LmCompatibilityLevel() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.LDAPClientIntegrity() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.NTLMMinClientSec() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.NTLMMinServerSec() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.ForceKeyProtection() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.ObCaseInsensitive() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.ProtectionMode() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.Optional() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.FilterAdministratorToken() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.EnableUIADesktopToggle() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.ConsentPromptBehaviorAdmin() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.ConsentPromptBehaviorUser() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.EnableInstallerDetection() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.EnableSecureUIAPaths() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.EnableLUA() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.PromptOnSecureDesktop() == 'NOT CONFIG') ==1 : notconfig +=1
	if (LocalPolicies.EnableVirtualization() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NCStdDomainUserSetLocation() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.SafeDllSearchMode() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AllowBasic() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NtpServer() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AllowIndexingEncryptedStoresOrItems() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.ExitOnMSICW() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Nonamereleaseondemand() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoBackgroundPolicy() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.fAllowUnsolicited() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.LocalAccountTokenFilterPolicy() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Retention3() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.EnableUserControl() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVPassphrase() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoHeapTerminationOnCorruption() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.TurnonResponder() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.ScreenSaverGracePeriod() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.SafeForScripting() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisablePasswordReveal() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoPublishingWizard() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVDiscoveryVolumeType() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.PasswordLength() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVRecovery() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.MaxDisconnectionTime() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableQueryRemoteServer() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoWebServices() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.ACSettingIndex1() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.TurnonMapperIO() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.fDisableLPT() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.MaxSize3() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.MaxSize2() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.MaxSize1() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.SpynetReporting() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AllowRemoteRPC() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.UseLogonCredential() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVAllowUserCert() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoInternetOpenWith() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.PreventHandwritingDataSharing() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableIPSourceRouting() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.ScenarioExecutionEnabled() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableWebPnPDownload() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.EnableAuthEpResolution() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.EnableScriptBlockLogging() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DCSettingIndex1() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoOnlinePrintsWizard() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVRecoveryKey() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.EncryptionMethod() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.UseTPMPIN() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AutoAdminLogon() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.EnableBDEWithNoTPM() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RestrictRemoteClients() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.EMETInstall() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.SysSettings() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DeleteTempDirsOnExit() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Peernet() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Registrars() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AllowDigest() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.OSRequireActiveDirectoryBackup() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.TurnOffSidebar() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoAUAsDefaultShutdownOption() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoDriveTypeAutoRun() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoRegistration() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.OSManageDRA() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AllowUnencryptedTraffic() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.PreventHandwritingErrorReports() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVHideRecoveryPage() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Defaults1() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoAutoUpdate() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.UseAdvancedStartup() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVDiscoveryVolumeType() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.UseTPMKeyPIN() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVRecovery() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVPassphrase() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.ASLR() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.EnumerateAdministrators() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableBkGndGroupPolicy() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVEnforceUserCert() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVActiveDirectoryBackup() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVActiveDirectoryInfoToStore() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Tcpmaxdataretransmissions() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVRecoveryKey() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.PerSessionTempDir() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoAUShutdownOption() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Defaults() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableHTTPPrinting() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DenyDeviceClasses() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AlwaysInstallElevated() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisablePasswordSaving() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.WindowsErrorReporting() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.fPromptForPassword() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableIP6SourceRouting() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.CEIP() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NCAllowNetBridgeNLA() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.PreXPSP2ShellProtocolBehavior() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AdmPwd() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.CEIPEnable() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableWcnUi() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Tcpmaxdataretransmissions6() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.PwdExpirationProtection() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVManageDRA() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.OSActiveDirectoryInfoToStore() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.PasswordAgeDays() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DEP() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoAutorun() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVRecoveryPassword() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.OSHideRecoveryPage() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoAutoRebootWithLoggedOnUsers() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.TurnOffUserInstalledGadgets() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.EnableICMPRedirect() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableLocation() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.OSActiveDirectoryBackup() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Retention1() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Retention2() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVManageDRA() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DCSettingIndex() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.UseTPMKey() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.PasswordComplexity() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DenyDeviceClasses1() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AdmPwdEnabled() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.LogonType() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RescheduleWaitTime() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AllowUnencryptedTrafficService() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.UseTPM() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.EnableTranscripting() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.ACSettingIndex() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVRecoveryPassword() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVEnforceUserCert() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.UseEnhancedPin() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AllowBasicService() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DenyDeviceClassesRetroactive() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoGPOListChanges() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.fDisableCcm() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVDenyWriteAccess() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableContentFileUpdates() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.MinEncryptionLevel() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVDenyCrossOrg() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.OSRecoveryPassword() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVRequireActiveDirectoryBackup() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.fDisablePNPRedir() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.OSRecoveryKey() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.ProcessCreationIncludeCmdLineEnabled() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.MaxSize() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.PerformRouterDiscovery() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableHomeGroup() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVHideRecoveryPage() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoDataExecutionPrevention() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.HardenedPaths() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVActiveDirectoryBackup() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.MinimumPIN() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVRequireActiveDirectoryBackup() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.fDenyTSConnections() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.fAllowToGetHelp() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Disablesavepassword() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.MaxIdleTime() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AllowRemoteShellAccess() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisabledComponents() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoAutoplayfornonVolume() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.WARNINGLevel() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.fDisableCdm() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.IE() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableRunAs() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.SEHOP() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NtpClient() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVAllowUserCert() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.KeepAliveTime() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.OSRecovery() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DefaultConsent() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableEnclosureDownload() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.ScheduledInstallDay() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVActiveDirectoryInfoToStore() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.fEncryptRPCTraffic() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Retention() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.NoImplicitFeedback() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.ScreenSaveTimeOut() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.ScreenSaverIsSecure() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.ScanWithAntiVirus() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.SaveZoneInformation() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.AlwaysInstallElevated() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.SCRNSAVE() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.NoInplaceSharing() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.PreventCodecDownload() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.ScreenSaveActive() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.get_user_sid() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditApplicationGroupManagement() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditSecuritySystemExtension() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditCredentialValidation() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditSensitivePrivilegeUse() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditAuthenticationPolicyChange() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditLogon() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditLogoff() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditProcessCreation() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditOtherSystemEvents() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditSystemIntegrity() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditAccountLockout() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditSpecialLogon() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditOtherLogonLogoffEvents() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditAuditPolicyChange() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditComputerAccountManagement() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditOtherAccountManagementEvents() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditSecurityStateChange() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditSecurityGroupManagement() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditIPsecDriver() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditUserAccountManagement() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallDomainProfile.Applylocalconnectionsecurityrules() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallDomainProfile.Firewallstate() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallDomainProfile.Displayanotification() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallDomainProfile.Applylocalfirewallrules() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallDomainProfile.Inboundconnections() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallDomainProfile.LogSuccessfulConnections() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallDomainProfile.LoggingCustomizeSize() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallDomainProfile.LoggingCustomizeName() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallDomainProfile.Logdroppedpackets() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallDomainProfile.Outboundconnections() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPrivateProfile.Applylocalconnectionsecurityrules() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPrivateProfile.Firewallstate() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPrivateProfile.Displayanotification() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPrivateProfile.Applylocalfirewallrules() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPrivateProfile.Inboundconnections() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPrivateProfile.LogSuccessfulConnections() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPrivateProfile.LoggingCustomizeSize() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPrivateProfile.LoggingCustomizeName() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPrivateProfile.Logdroppedpackets() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPrivateProfile.Outboundconnections() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPublicProfile.Applylocalconnectionsecurityrules() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPublicProfile.Firewallstate() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPublicProfile.Displayanotification() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPublicProfile.Applylocalfirewallrules() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPublicProfile.Inboundconnections() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPublicProfile.LogSuccessfulConnections() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPublicProfile.LoggingCustomizeSize() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPublicProfile.LoggingCustomizeName() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPublicProfile.Logdroppedpackets() == 'NOT CONFIG') ==1 : notconfig +=1
	if (FirewallPublicProfile.Outboundconnections() == 'NOT CONFIG') ==1 : notconfig +=1
	if (AccountPolicies.PasswordHistorySize() == 'NOT FOUND') ==1 : notconfig +=1
	if (AccountPolicies.MaximumPasswordAge() == 'NOT FOUND') ==1 : notconfig +=1
	if (AccountPolicies.MinimumPasswordAge() == 'NOT FOUND') ==1 : notconfig +=1
	if (AccountPolicies.MinimumPasswordLength() == 'NOT FOUND') ==1 : notconfig +=1
	if (AccountPolicies.PasswordComplexity() == 'NOT FOUND') ==1 : notconfig +=1
	if (AccountPolicies.ClearTextPassword() == 'NOT FOUND') ==1 : notconfig +=1
	if (AccountPolicies.LockoutDuration() == 'NOT FOUND') ==1 : notconfig +=1
	if (AccountPolicies.LockoutBadCount() == 'NOT FOUND') ==1 : notconfig +=1
	if (AccountPolicies.ResetLockoutCount() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeTrustedCredManAccessPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeNetworkLogonRight() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeTcbPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeIncreaseQuotaPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeInteractiveLogonRight() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeRemoteInteractiveLogonRight() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeBackupPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeIncreaseBasePriorityPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeSystemtimePrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeTimeZonePrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeCreatePagefilePrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeCreateTokenPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeCreateGlobalPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeCreatePermanentPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeCreateSymbolicLinkPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeDebugPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeDenyNetworkLogonRight() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeDenyBatchLogonRight() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeDenyServiceLogonRight() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeDenyInteractiveLogonRight() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeDenyRemoteInteractiveLogonRight() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeEnableDelegationPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeRemoteShutdownPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeAuditPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeImpersonatePrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeLoadDriverPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeLockMemoryPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeBatchLogonRight() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeServiceLogonRight() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeSecurityPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeRelabelPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeSystemEnvironmentPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeManageVolumePrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeSystemProfilePrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeProfileSingleProcessPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeAssignPrimaryTokenPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeRestorePrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeShutdownPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SeTakeOwnershipPrivilege() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.EnableAdminAccount() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.EnableGuestAccount() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.LimitBlankPasswordUse() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.NewAdministratorName() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.NewGuestName() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SCENoApplyLegacyAuditPolicy() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.crashonauditfail() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.AllocateDASD() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.AddPrinterDriver() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.RequireSignOrSeal() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SealSecureChannel() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SignSecureChannel() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.DisablePasswordChange() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.MaximumPasswordAge() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.RequireStrongKey() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.DontDisplayLastUserName() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.DisableCAD() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.LegalNoticeText() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.LegalNoticeCaption() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.CachedLogonsCount() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.PasswordExpiryWARNING() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.ScRemoveOption() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.RequireSecuritySignature() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.EnableSecuritySignature() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.EnablePlainTextPassword() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.autodisconnect() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.RequireSecuritySignatureServer() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.EnableSecuritySignatureServer() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.enableforcedlogoff() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SMBServerNameHardeningLevel() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.LSAAnonymousNameLookup() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.RestrictAnonymousSAM() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.RestrictAnonymous() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.disabledomaincreds() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.EveryoneIncludesAnonymous() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.NullSessionPipes() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.AllowedExactPaths() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.AllowedPaths() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.restrictnullsessaccess() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.NullSessionShares() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.ForceGuest() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.UseMachineId() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.allownullsessionfallback() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.AllowOnlineID() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.SupportedEncryptionTypes() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.NoLMHash() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.enableforcedlogoff1() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.LmCompatibilityLevel() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.LDAPClientIntegrity() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.NTLMMinClientSec() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.NTLMMinServerSec() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.ForceKeyProtection() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.ObCaseInsensitive() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.ProtectionMode() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.Optional() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.FilterAdministratorToken() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.EnableUIADesktopToggle() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.ConsentPromptBehaviorAdmin() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.ConsentPromptBehaviorUser() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.EnableInstallerDetection() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.EnableSecureUIAPaths() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.EnableLUA() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.PromptOnSecureDesktop() == 'NOT FOUND') ==1 : notconfig +=1
	if (LocalPolicies.EnableVirtualization() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NCStdDomainUserSetLocation() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.SafeDllSearchMode() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AllowBasic() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NtpServer() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AllowIndexingEncryptedStoresOrItems() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.ExitOnMSICW() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Nonamereleaseondemand() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoBackgroundPolicy() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.fAllowUnsolicited() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.LocalAccountTokenFilterPolicy() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Retention3() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.EnableUserControl() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVPassphrase() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoHeapTerminationOnCorruption() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.TurnonResponder() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.ScreenSaverGracePeriod() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.SafeForScripting() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisablePasswordReveal() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoPublishingWizard() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVDiscoveryVolumeType() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.PasswordLength() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVRecovery() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.MaxDisconnectionTime() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableQueryRemoteServer() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoWebServices() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.ACSettingIndex1() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.TurnonMapperIO() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.fDisableLPT() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.MaxSize3() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.MaxSize2() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.MaxSize1() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.SpynetReporting() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AllowRemoteRPC() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.UseLogonCredential() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVAllowUserCert() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoInternetOpenWith() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.PreventHandwritingDataSharing() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableIPSourceRouting() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.ScenarioExecutionEnabled() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableWebPnPDownload() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.EnableAuthEpResolution() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.EnableScriptBlockLogging() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DCSettingIndex1() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoOnlinePrintsWizard() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVRecoveryKey() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.EncryptionMethod() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.UseTPMPIN() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AutoAdminLogon() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.EnableBDEWithNoTPM() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RestrictRemoteClients() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.EMETInstall() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.SysSettings() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DeleteTempDirsOnExit() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Peernet() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Registrars() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AllowDigest() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.OSRequireActiveDirectoryBackup() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.TurnOffSidebar() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoAUAsDefaultShutdownOption() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoDriveTypeAutoRun() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoRegistration() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.OSManageDRA() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AllowUnencryptedTraffic() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.PreventHandwritingErrorReports() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVHideRecoveryPage() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Defaults1() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoAutoUpdate() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.UseAdvancedStartup() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVDiscoveryVolumeType() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.UseTPMKeyPIN() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVRecovery() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVPassphrase() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.ASLR() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.EnumerateAdministrators() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableBkGndGroupPolicy() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVEnforceUserCert() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVActiveDirectoryBackup() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVActiveDirectoryInfoToStore() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Tcpmaxdataretransmissions() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVRecoveryKey() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.PerSessionTempDir() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoAUShutdownOption() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Defaults() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableHTTPPrinting() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DenyDeviceClasses() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AlwaysInstallElevated() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisablePasswordSaving() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.WindowsErrorReporting() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.fPromptForPassword() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableIP6SourceRouting() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.CEIP() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NCAllowNetBridgeNLA() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.PreXPSP2ShellProtocolBehavior() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AdmPwd() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.CEIPEnable() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableWcnUi() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Tcpmaxdataretransmissions6() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.PwdExpirationProtection() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVManageDRA() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.OSActiveDirectoryInfoToStore() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.PasswordAgeDays() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DEP() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoAutorun() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVRecoveryPassword() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.OSHideRecoveryPage() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoAutoRebootWithLoggedOnUsers() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.TurnOffUserInstalledGadgets() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.EnableICMPRedirect() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableLocation() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.OSActiveDirectoryBackup() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Retention1() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Retention2() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVManageDRA() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DCSettingIndex() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.UseTPMKey() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.PasswordComplexity() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DenyDeviceClasses1() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AdmPwdEnabled() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.LogonType() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RescheduleWaitTime() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AllowUnencryptedTrafficService() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.UseTPM() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.EnableTranscripting() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.ACSettingIndex() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVRecoveryPassword() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVEnforceUserCert() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.UseEnhancedPin() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AllowBasicService() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DenyDeviceClassesRetroactive() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoGPOListChanges() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.fDisableCcm() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVDenyWriteAccess() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableContentFileUpdates() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.MinEncryptionLevel() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVDenyCrossOrg() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.OSRecoveryPassword() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVRequireActiveDirectoryBackup() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.fDisablePNPRedir() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.OSRecoveryKey() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.ProcessCreationIncludeCmdLineEnabled() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.MaxSize() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.PerformRouterDiscovery() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableHomeGroup() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVHideRecoveryPage() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoDataExecutionPrevention() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.HardenedPaths() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVActiveDirectoryBackup() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.MinimumPIN() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVRequireActiveDirectoryBackup() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.fDenyTSConnections() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.fAllowToGetHelp() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Disablesavepassword() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.MaxIdleTime() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.AllowRemoteShellAccess() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisabledComponents() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NoAutoplayfornonVolume() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.WARNINGLevel() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.fDisableCdm() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.IE() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableRunAs() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.SEHOP() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.NtpClient() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.RDVAllowUserCert() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.KeepAliveTime() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.OSRecovery() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DefaultConsent() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.DisableEnclosureDownload() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.ScheduledInstallDay() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.FDVActiveDirectoryInfoToStore() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.fEncryptRPCTraffic() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesComputer.Retention() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.NoImplicitFeedback() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.ScreenSaveTimeOut() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.ScreenSaverIsSecure() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.ScanWithAntiVirus() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.SaveZoneInformation() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.AlwaysInstallElevated() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.SCRNSAVE() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.NoInplaceSharing() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.PreventCodecDownload() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.ScreenSaveActive() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdministrativeTemplatesUser.get_user_sid() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditApplicationGroupManagement() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditSecuritySystemExtension() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditCredentialValidation() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditSensitivePrivilegeUse() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditAuthenticationPolicyChange() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditLogon() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditLogoff() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditProcessCreation() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditOtherSystemEvents() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditSystemIntegrity() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditAccountLockout() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditSpecialLogon() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditOtherLogonLogoffEvents() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditAuditPolicyChange() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditComputerAccountManagement() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditOtherAccountManagementEvents() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditSecurityStateChange() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditSecurityGroupManagement() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditIPsecDriver() == 'NOT FOUND') ==1 : notconfig +=1
	if (AdvancedAuditPolicyConfiguration.AuditUserAccountManagement() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallDomainProfile.Applylocalconnectionsecurityrules() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallDomainProfile.Firewallstate() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallDomainProfile.Displayanotification() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallDomainProfile.Applylocalfirewallrules() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallDomainProfile.Inboundconnections() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallDomainProfile.LogSuccessfulConnections() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallDomainProfile.LoggingCustomizeSize() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallDomainProfile.LoggingCustomizeName() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallDomainProfile.Logdroppedpackets() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallDomainProfile.Outboundconnections() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPrivateProfile.Applylocalconnectionsecurityrules() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPrivateProfile.Firewallstate() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPrivateProfile.Displayanotification() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPrivateProfile.Applylocalfirewallrules() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPrivateProfile.Inboundconnections() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPrivateProfile.LogSuccessfulConnections() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPrivateProfile.LoggingCustomizeSize() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPrivateProfile.LoggingCustomizeName() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPrivateProfile.Logdroppedpackets() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPrivateProfile.Outboundconnections() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPublicProfile.Applylocalconnectionsecurityrules() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPublicProfile.Firewallstate() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPublicProfile.Displayanotification() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPublicProfile.Applylocalfirewallrules() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPublicProfile.Inboundconnections() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPublicProfile.LogSuccessfulConnections() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPublicProfile.LoggingCustomizeSize() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPublicProfile.LoggingCustomizeName() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPublicProfile.Logdroppedpackets() == 'NOT FOUND') ==1 : notconfig +=1
	if (FirewallPublicProfile.Outboundconnections() == 'NOT FOUND') ==1 : notconfig +=1
	return notconfig
def ok():
	temp = 0
	if (AccountPolicies.PasswordHistorySize() == 'OK') ==1 : temp +=1
	if (AccountPolicies.MaximumPasswordAge() == 'OK') ==1 : temp +=1
	if (AccountPolicies.MinimumPasswordAge() == 'OK') ==1 : temp +=1
	if (AccountPolicies.MinimumPasswordLength() == 'OK') ==1 : temp +=1
	if (AccountPolicies.PasswordComplexity() == 'OK') ==1 : temp +=1
	if (AccountPolicies.ClearTextPassword() == 'OK') ==1 : temp +=1
	if (AccountPolicies.LockoutDuration() == 'OK') ==1 : temp +=1
	if (AccountPolicies.LockoutBadCount() == 'OK') ==1 : temp +=1
	if (AccountPolicies.ResetLockoutCount() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeTrustedCredManAccessPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeNetworkLogonRight() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeTcbPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeIncreaseQuotaPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeInteractiveLogonRight() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeRemoteInteractiveLogonRight() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeBackupPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeSystemtimePrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeTimeZonePrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeCreatePagefilePrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeCreateTokenPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeCreateGlobalPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeCreatePermanentPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeCreateSymbolicLinkPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeDebugPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeDenyNetworkLogonRight() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeDenyBatchLogonRight() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeDenyServiceLogonRight() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeDenyInteractiveLogonRight() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeDenyRemoteInteractiveLogonRight() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeEnableDelegationPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeRemoteShutdownPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeAuditPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeImpersonatePrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeIncreaseBasePriorityPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeLoadDriverPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeLockMemoryPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeBatchLogonRight() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeServiceLogonRight() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeSecurityPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeRelabelPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeSystemEnvironmentPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeManageVolumePrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeSystemProfilePrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeProfileSingleProcessPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeAssignPrimaryTokenPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeRestorePrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeShutdownPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SeTakeOwnershipPrivilege() == 'OK') ==1 : temp +=1
	if (LocalPolicies.EnableAdminAccount() == 'OK') ==1 : temp +=1
	if (LocalPolicies.EnableGuestAccount() == 'OK') ==1 : temp +=1
	if (LocalPolicies.LimitBlankPasswordUse() == 'OK') ==1 : temp +=1
	if (LocalPolicies.NewAdministratorName() == 'OK') ==1 : temp +=1
	if (LocalPolicies.NewGuestName() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SCENoApplyLegacyAuditPolicy() == 'OK') ==1 : temp +=1
	if (LocalPolicies.crashonauditfail() == 'OK') ==1 : temp +=1
	if (LocalPolicies.AllocateDASD() == 'OK') ==1 : temp +=1
	if (LocalPolicies.AddPrinterDriver() == 'OK') ==1 : temp +=1
	if (LocalPolicies.RequireSignOrSeal() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SealSecureChannel() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SignSecureChannel() == 'OK') ==1 : temp +=1
	if (LocalPolicies.DisablePasswordChange() == 'OK') ==1 : temp +=1
	if (LocalPolicies.MaximumPasswordAge() == 'OK') ==1 : temp +=1
	if (LocalPolicies.RequireStrongKey() == 'OK') ==1 : temp +=1
	if (LocalPolicies.DontDisplayLastUserName() == 'OK') ==1 : temp +=1
	if (LocalPolicies.DisableCAD() == 'OK') ==1 : temp +=1
	if (LocalPolicies.LegalNoticeText() == 'OK') ==1 : temp +=1
	if (LocalPolicies.LegalNoticeCaption() == 'OK') ==1 : temp +=1
	if (LocalPolicies.CachedLogonsCount() == 'OK') ==1 : temp +=1
	if (LocalPolicies.PasswordExpiryWARNING() == 'OK') ==1 : temp +=1
	if (LocalPolicies.ScRemoveOption() == 'OK') ==1 : temp +=1
	if (LocalPolicies.RequireSecuritySignature() == 'OK') ==1 : temp +=1
	if (LocalPolicies.EnableSecuritySignature() == 'OK') ==1 : temp +=1
	if (LocalPolicies.EnablePlainTextPassword() == 'OK') ==1 : temp +=1
	if (LocalPolicies.autodisconnect() == 'OK') ==1 : temp +=1
	if (LocalPolicies.RequireSecuritySignatureServer() == 'OK') ==1 : temp +=1
	if (LocalPolicies.EnableSecuritySignatureServer() == 'OK') ==1 : temp +=1
	if (LocalPolicies.enableforcedlogoff() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SMBServerNameHardeningLevel() == 'OK') ==1 : temp +=1
	if (LocalPolicies.LSAAnonymousNameLookup() == 'OK') ==1 : temp +=1
	if (LocalPolicies.RestrictAnonymousSAM() == 'OK') ==1 : temp +=1
	if (LocalPolicies.RestrictAnonymous() == 'OK') ==1 : temp +=1
	if (LocalPolicies.disabledomaincreds() == 'OK') ==1 : temp +=1
	if (LocalPolicies.EveryoneIncludesAnonymous() == 'OK') ==1 : temp +=1
	if (LocalPolicies.NullSessionPipes() == 'OK') ==1 : temp +=1
	if (LocalPolicies.AllowedExactPaths() == 'OK') ==1 : temp +=1
	if (LocalPolicies.AllowedPaths() == 'OK') ==1 : temp +=1
	if (LocalPolicies.restrictnullsessaccess() == 'OK') ==1 : temp +=1
	if (LocalPolicies.NullSessionShares() == 'OK') ==1 : temp +=1
	if (LocalPolicies.ForceGuest() == 'OK') ==1 : temp +=1
	if (LocalPolicies.UseMachineId() == 'OK') ==1 : temp +=1
	if (LocalPolicies.allownullsessionfallback() == 'OK') ==1 : temp +=1
	if (LocalPolicies.AllowOnlineID() == 'OK') ==1 : temp +=1
	if (LocalPolicies.SupportedEncryptionTypes() == 'OK') ==1 : temp +=1
	if (LocalPolicies.NoLMHash() == 'OK') ==1 : temp +=1
	if (LocalPolicies.enableforcedlogoff1() == 'OK') ==1 : temp +=1
	if (LocalPolicies.LmCompatibilityLevel() == 'OK') ==1 : temp +=1
	if (LocalPolicies.LDAPClientIntegrity() == 'OK') ==1 : temp +=1
	if (LocalPolicies.NTLMMinClientSec() == 'OK') ==1 : temp +=1
	if (LocalPolicies.NTLMMinServerSec() == 'OK') ==1 : temp +=1
	if (LocalPolicies.ForceKeyProtection() == 'OK') ==1 : temp +=1
	if (LocalPolicies.ObCaseInsensitive() == 'OK') ==1 : temp +=1
	if (LocalPolicies.ProtectionMode() == 'OK') ==1 : temp +=1
	if (LocalPolicies.Optional() == 'OK') ==1 : temp +=1
	if (LocalPolicies.FilterAdministratorToken() == 'OK') ==1 : temp +=1
	if (LocalPolicies.EnableUIADesktopToggle() == 'OK') ==1 : temp +=1
	if (LocalPolicies.ConsentPromptBehaviorAdmin() == 'OK') ==1 : temp +=1
	if (LocalPolicies.ConsentPromptBehaviorUser() == 'OK') ==1 : temp +=1
	if (LocalPolicies.EnableInstallerDetection() == 'OK') ==1 : temp +=1
	if (LocalPolicies.EnableSecureUIAPaths() == 'OK') ==1 : temp +=1
	if (LocalPolicies.EnableLUA() == 'OK') ==1 : temp +=1
	if (LocalPolicies.PromptOnSecureDesktop() == 'OK') ==1 : temp +=1
	if (LocalPolicies.EnableVirtualization() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NCStdDomainUserSetLocation() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.SafeDllSearchMode() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AllowBasic() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NtpServer() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AllowIndexingEncryptedStoresOrItems() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.ExitOnMSICW() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Nonamereleaseondemand() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoBackgroundPolicy() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.fAllowUnsolicited() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.LocalAccountTokenFilterPolicy() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Retention3() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.EnableUserControl() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVPassphrase() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoHeapTerminationOnCorruption() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.TurnonResponder() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.ScreenSaverGracePeriod() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.SafeForScripting() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisablePasswordReveal() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoPublishingWizard() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVDiscoveryVolumeType() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.PasswordLength() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVRecovery() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.MaxDisconnectionTime() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableQueryRemoteServer() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoWebServices() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.ACSettingIndex1() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.TurnonMapperIO() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.fDisableLPT() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.MaxSize3() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.MaxSize2() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.MaxSize1() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.SpynetReporting() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AllowRemoteRPC() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.UseLogonCredential() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVAllowUserCert() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoInternetOpenWith() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.PreventHandwritingDataSharing() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableIPSourceRouting() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.ScenarioExecutionEnabled() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableWebPnPDownload() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.EnableAuthEpResolution() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.EnableScriptBlockLogging() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DCSettingIndex1() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoOnlinePrintsWizard() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVRecoveryKey() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.EncryptionMethod() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.UseTPMPIN() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AutoAdminLogon() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.EnableBDEWithNoTPM() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RestrictRemoteClients() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.EMETInstall() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.SysSettings() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DeleteTempDirsOnExit() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Peernet() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Registrars() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AllowDigest() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.OSRequireActiveDirectoryBackup() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.TurnOffSidebar() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoAUAsDefaultShutdownOption() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoDriveTypeAutoRun() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoRegistration() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.OSManageDRA() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AllowUnencryptedTraffic() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.PreventHandwritingErrorReports() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVHideRecoveryPage() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Defaults1() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoAutoUpdate() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.UseAdvancedStartup() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVDiscoveryVolumeType() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.UseTPMKeyPIN() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVRecovery() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVPassphrase() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.ASLR() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.EnumerateAdministrators() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableBkGndGroupPolicy() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVEnforceUserCert() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVActiveDirectoryBackup() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVActiveDirectoryInfoToStore() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Tcpmaxdataretransmissions() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVRecoveryKey() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.PerSessionTempDir() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoAUShutdownOption() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Defaults() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableHTTPPrinting() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DenyDeviceClasses() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AlwaysInstallElevated() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisablePasswordSaving() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.WindowsErrorReporting() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.fPromptForPassword() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableIP6SourceRouting() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.CEIP() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NCAllowNetBridgeNLA() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.PreXPSP2ShellProtocolBehavior() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AdmPwd() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.CEIPEnable() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableWcnUi() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Tcpmaxdataretransmissions6() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.PwdExpirationProtection() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVManageDRA() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.OSActiveDirectoryInfoToStore() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.PasswordAgeDays() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DEP() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoAutorun() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVRecoveryPassword() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.OSHideRecoveryPage() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoAutoRebootWithLoggedOnUsers() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.TurnOffUserInstalledGadgets() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.EnableICMPRedirect() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableLocation() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.OSActiveDirectoryBackup() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Retention1() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Retention2() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVManageDRA() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DCSettingIndex() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.UseTPMKey() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.PasswordComplexity() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DenyDeviceClasses1() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AdmPwdEnabled() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.LogonType() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RescheduleWaitTime() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AllowUnencryptedTrafficService() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.UseTPM() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.EnableTranscripting() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.ACSettingIndex() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVRecoveryPassword() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVEnforceUserCert() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.UseEnhancedPin() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AllowBasicService() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DenyDeviceClassesRetroactive() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoGPOListChanges() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.fDisableCcm() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVDenyWriteAccess() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableContentFileUpdates() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.MinEncryptionLevel() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVDenyCrossOrg() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.OSRecoveryPassword() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVRequireActiveDirectoryBackup() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.fDisablePNPRedir() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.OSRecoveryKey() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.ProcessCreationIncludeCmdLineEnabled() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.MaxSize() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.PerformRouterDiscovery() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableHomeGroup() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVHideRecoveryPage() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoDataExecutionPrevention() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.HardenedPaths() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVActiveDirectoryBackup() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.MinimumPIN() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVRequireActiveDirectoryBackup() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.fDenyTSConnections() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.fAllowToGetHelp() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Disablesavepassword() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.MaxIdleTime() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AllowRemoteShellAccess() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisabledComponents() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoAutoplayfornonVolume() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.WARNINGLevel() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.fDisableCdm() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.IE() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableRunAs() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.SEHOP() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NtpClient() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVAllowUserCert() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.KeepAliveTime() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.OSRecovery() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DefaultConsent() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableEnclosureDownload() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.ScheduledInstallDay() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVActiveDirectoryInfoToStore() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.fEncryptRPCTraffic() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Retention() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesUser.NoImplicitFeedback() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesUser.ScreenSaveTimeOut() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesUser.ScreenSaverIsSecure() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesUser.ScanWithAntiVirus() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesUser.SaveZoneInformation() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesUser.AlwaysInstallElevated() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesUser.SCRNSAVE() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesUser.NoInplaceSharing() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesUser.PreventCodecDownload() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesUser.ScreenSaveActive() == 'OK') ==1 : temp +=1
	if (AdministrativeTemplatesUser.get_user_sid() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditApplicationGroupManagement() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditSecuritySystemExtension() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditCredentialValidation() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditSensitivePrivilegeUse() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditAuthenticationPolicyChange() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditLogon() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditLogoff() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditProcessCreation() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditOtherSystemEvents() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditSystemIntegrity() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditAccountLockout() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditSpecialLogon() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditOtherLogonLogoffEvents() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditAuditPolicyChange() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditComputerAccountManagement() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditOtherAccountManagementEvents() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditSecurityStateChange() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditSecurityGroupManagement() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditIPsecDriver() == 'OK') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditUserAccountManagement() == 'OK') ==1 : temp +=1
	if (FirewallDomainProfile.Applylocalconnectionsecurityrules() == 'OK') ==1 : temp +=1
	if (FirewallDomainProfile.Firewallstate() == 'OK') ==1 : temp +=1
	if (FirewallDomainProfile.Displayanotification() == 'OK') ==1 : temp +=1
	if (FirewallDomainProfile.Applylocalfirewallrules() == 'OK') ==1 : temp +=1
	if (FirewallDomainProfile.Inboundconnections() == 'OK') ==1 : temp +=1
	if (FirewallDomainProfile.LogSuccessfulConnections() == 'OK') ==1 : temp +=1
	if (FirewallDomainProfile.LoggingCustomizeSize() == 'OK') ==1 : temp +=1
	if (FirewallDomainProfile.LoggingCustomizeName() == 'OK') ==1 : temp +=1
	if (FirewallDomainProfile.Logdroppedpackets() == 'OK') ==1 : temp +=1
	if (FirewallDomainProfile.Outboundconnections() == 'OK') ==1 : temp +=1
	if (FirewallPrivateProfile.Applylocalconnectionsecurityrules() == 'OK') ==1 : temp +=1
	if (FirewallPrivateProfile.Firewallstate() == 'OK') ==1 : temp +=1
	if (FirewallPrivateProfile.Displayanotification() == 'OK') ==1 : temp +=1
	if (FirewallPrivateProfile.Applylocalfirewallrules() == 'OK') ==1 : temp +=1
	if (FirewallPrivateProfile.Inboundconnections() == 'OK') ==1 : temp +=1
	if (FirewallPrivateProfile.LogSuccessfulConnections() == 'OK') ==1 : temp +=1
	if (FirewallPrivateProfile.LoggingCustomizeSize() == 'OK') ==1 : temp +=1
	if (FirewallPrivateProfile.LoggingCustomizeName() == 'OK') ==1 : temp +=1
	if (FirewallPrivateProfile.Logdroppedpackets() == 'OK') ==1 : temp +=1
	if (FirewallPrivateProfile.Outboundconnections() == 'OK') ==1 : temp +=1
	if (FirewallPublicProfile.Applylocalconnectionsecurityrules() == 'OK') ==1 : temp +=1
	if (FirewallPublicProfile.Firewallstate() == 'OK') ==1 : temp +=1
	if (FirewallPublicProfile.Displayanotification() == 'OK') ==1 : temp +=1
	if (FirewallPublicProfile.Applylocalfirewallrules() == 'OK') ==1 : temp +=1
	if (FirewallPublicProfile.Inboundconnections() == 'OK') ==1 : temp +=1
	if (FirewallPublicProfile.LogSuccessfulConnections() == 'OK') ==1 : temp +=1
	if (FirewallPublicProfile.LoggingCustomizeSize() == 'OK') ==1 : temp +=1
	if (FirewallPublicProfile.LoggingCustomizeName() == 'OK') ==1 : temp +=1
	if (FirewallPublicProfile.Logdroppedpackets() == 'OK') ==1 : temp +=1
	if (FirewallPublicProfile.Outboundconnections() == 'OK') ==1 : temp +=1
	if (AccountPolicies.PasswordHistorySize() == 'GOOD') ==1 : temp +=1
	if (AccountPolicies.MaximumPasswordAge() == 'GOOD') ==1 : temp +=1
	if (AccountPolicies.MinimumPasswordAge() == 'GOOD') ==1 : temp +=1
	if (AccountPolicies.MinimumPasswordLength() == 'GOOD') ==1 : temp +=1
	if (AccountPolicies.PasswordComplexity() == 'GOOD') ==1 : temp +=1
	if (AccountPolicies.ClearTextPassword() == 'GOOD') ==1 : temp +=1
	if (AccountPolicies.LockoutDuration() == 'GOOD') ==1 : temp +=1
	if (AccountPolicies.LockoutBadCount() == 'GOOD') ==1 : temp +=1
	if (AccountPolicies.ResetLockoutCount() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeTrustedCredManAccessPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeNetworkLogonRight() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeTcbPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeIncreaseQuotaPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeInteractiveLogonRight() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeRemoteInteractiveLogonRight() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeBackupPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeSystemtimePrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeTimeZonePrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeCreatePagefilePrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeCreateTokenPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeCreateGlobalPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeCreatePermanentPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeCreateSymbolicLinkPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeDebugPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeDenyNetworkLogonRight() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeDenyBatchLogonRight() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeDenyServiceLogonRight() == 'GOOD') ==1 : temp +=1	
	if (LocalPolicies.SeIncreaseBasePriorityPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeDenyInteractiveLogonRight() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeDenyRemoteInteractiveLogonRight() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeEnableDelegationPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeRemoteShutdownPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeAuditPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeImpersonatePrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeLoadDriverPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeLockMemoryPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeBatchLogonRight() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeServiceLogonRight() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeSecurityPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeRelabelPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeSystemEnvironmentPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeManageVolumePrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeSystemProfilePrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeProfileSingleProcessPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeAssignPrimaryTokenPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeRestorePrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeShutdownPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SeTakeOwnershipPrivilege() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.EnableAdminAccount() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.EnableGuestAccount() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.LimitBlankPasswordUse() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.NewAdministratorName() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.NewGuestName() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SCENoApplyLegacyAuditPolicy() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.crashonauditfail() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.AllocateDASD() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.AddPrinterDriver() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.RequireSignOrSeal() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SealSecureChannel() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SignSecureChannel() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.DisablePasswordChange() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.MaximumPasswordAge() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.RequireStrongKey() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.DontDisplayLastUserName() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.DisableCAD() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.LegalNoticeText() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.LegalNoticeCaption() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.CachedLogonsCount() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.PasswordExpiryWARNING() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.ScRemoveOption() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.RequireSecuritySignature() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.EnableSecuritySignature() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.EnablePlainTextPassword() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.autodisconnect() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.RequireSecuritySignatureServer() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.EnableSecuritySignatureServer() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.enableforcedlogoff() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SMBServerNameHardeningLevel() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.LSAAnonymousNameLookup() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.RestrictAnonymousSAM() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.RestrictAnonymous() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.disabledomaincreds() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.EveryoneIncludesAnonymous() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.NullSessionPipes() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.AllowedExactPaths() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.AllowedPaths() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.restrictnullsessaccess() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.NullSessionShares() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.ForceGuest() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.UseMachineId() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.allownullsessionfallback() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.AllowOnlineID() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.SupportedEncryptionTypes() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.NoLMHash() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.enableforcedlogoff1() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.LmCompatibilityLevel() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.LDAPClientIntegrity() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.NTLMMinClientSec() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.NTLMMinServerSec() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.ForceKeyProtection() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.ObCaseInsensitive() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.ProtectionMode() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.Optional() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.FilterAdministratorToken() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.EnableUIADesktopToggle() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.ConsentPromptBehaviorAdmin() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.ConsentPromptBehaviorUser() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.EnableInstallerDetection() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.EnableSecureUIAPaths() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.EnableLUA() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.PromptOnSecureDesktop() == 'GOOD') ==1 : temp +=1
	if (LocalPolicies.EnableVirtualization() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NCStdDomainUserSetLocation() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.SafeDllSearchMode() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AllowBasic() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NtpServer() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AllowIndexingEncryptedStoresOrItems() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.ExitOnMSICW() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Nonamereleaseondemand() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoBackgroundPolicy() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.fAllowUnsolicited() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.LocalAccountTokenFilterPolicy() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Retention3() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.EnableUserControl() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVPassphrase() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoHeapTerminationOnCorruption() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.TurnonResponder() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.ScreenSaverGracePeriod() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.SafeForScripting() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisablePasswordReveal() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoPublishingWizard() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVDiscoveryVolumeType() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.PasswordLength() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVRecovery() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.MaxDisconnectionTime() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableQueryRemoteServer() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoWebServices() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.ACSettingIndex1() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.TurnonMapperIO() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.fDisableLPT() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.MaxSize3() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.MaxSize2() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.MaxSize1() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.SpynetReporting() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AllowRemoteRPC() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.UseLogonCredential() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVAllowUserCert() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoInternetOpenWith() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.PreventHandwritingDataSharing() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableIPSourceRouting() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.ScenarioExecutionEnabled() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableWebPnPDownload() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.EnableAuthEpResolution() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.EnableScriptBlockLogging() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DCSettingIndex1() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoOnlinePrintsWizard() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVRecoveryKey() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.EncryptionMethod() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.UseTPMPIN() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AutoAdminLogon() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.EnableBDEWithNoTPM() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RestrictRemoteClients() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.EMETInstall() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.SysSettings() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DeleteTempDirsOnExit() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Peernet() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Registrars() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AllowDigest() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.OSRequireActiveDirectoryBackup() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.TurnOffSidebar() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoAUAsDefaultShutdownOption() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoDriveTypeAutoRun() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoRegistration() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.OSManageDRA() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AllowUnencryptedTraffic() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.PreventHandwritingErrorReports() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVHideRecoveryPage() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Defaults1() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoAutoUpdate() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.UseAdvancedStartup() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVDiscoveryVolumeType() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.UseTPMKeyPIN() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVRecovery() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVPassphrase() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.ASLR() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.EnumerateAdministrators() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableBkGndGroupPolicy() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVEnforceUserCert() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVActiveDirectoryBackup() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVActiveDirectoryInfoToStore() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Tcpmaxdataretransmissions() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVRecoveryKey() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.PerSessionTempDir() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoAUShutdownOption() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Defaults() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableHTTPPrinting() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DenyDeviceClasses() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AlwaysInstallElevated() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisablePasswordSaving() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.WindowsErrorReporting() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.fPromptForPassword() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableIP6SourceRouting() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.CEIP() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NCAllowNetBridgeNLA() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.PreXPSP2ShellProtocolBehavior() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AdmPwd() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.CEIPEnable() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableWcnUi() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Tcpmaxdataretransmissions6() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.PwdExpirationProtection() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVManageDRA() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.OSActiveDirectoryInfoToStore() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.PasswordAgeDays() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DEP() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoAutorun() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVRecoveryPassword() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.OSHideRecoveryPage() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoAutoRebootWithLoggedOnUsers() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.TurnOffUserInstalledGadgets() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.EnableICMPRedirect() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableLocation() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.OSActiveDirectoryBackup() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Retention1() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Retention2() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVManageDRA() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DCSettingIndex() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.UseTPMKey() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.PasswordComplexity() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DenyDeviceClasses1() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AdmPwdEnabled() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.LogonType() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RescheduleWaitTime() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AllowUnencryptedTrafficService() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.UseTPM() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.EnableTranscripting() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.ACSettingIndex() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVRecoveryPassword() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVEnforceUserCert() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.UseEnhancedPin() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AllowBasicService() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DenyDeviceClassesRetroactive() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoGPOListChanges() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.fDisableCcm() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVDenyWriteAccess() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableContentFileUpdates() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.MinEncryptionLevel() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVDenyCrossOrg() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.OSRecoveryPassword() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVRequireActiveDirectoryBackup() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.fDisablePNPRedir() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.OSRecoveryKey() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.ProcessCreationIncludeCmdLineEnabled() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.MaxSize() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.PerformRouterDiscovery() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableHomeGroup() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVHideRecoveryPage() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoDataExecutionPrevention() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.HardenedPaths() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVActiveDirectoryBackup() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.MinimumPIN() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVRequireActiveDirectoryBackup() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.fDenyTSConnections() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.fAllowToGetHelp() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Disablesavepassword() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.MaxIdleTime() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.AllowRemoteShellAccess() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisabledComponents() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NoAutoplayfornonVolume() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.WARNINGLevel() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.fDisableCdm() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.IE() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableRunAs() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.SEHOP() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.NtpClient() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.RDVAllowUserCert() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.KeepAliveTime() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.OSRecovery() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DefaultConsent() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.DisableEnclosureDownload() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.ScheduledInstallDay() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.FDVActiveDirectoryInfoToStore() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.fEncryptRPCTraffic() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesComputer.Retention() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesUser.NoImplicitFeedback() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesUser.ScreenSaveTimeOut() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesUser.ScreenSaverIsSecure() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesUser.ScanWithAntiVirus() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesUser.SaveZoneInformation() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesUser.AlwaysInstallElevated() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesUser.SCRNSAVE() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesUser.NoInplaceSharing() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesUser.PreventCodecDownload() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesUser.ScreenSaveActive() == 'GOOD') ==1 : temp +=1
	if (AdministrativeTemplatesUser.get_user_sid() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditApplicationGroupManagement() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditSecuritySystemExtension() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditCredentialValidation() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditSensitivePrivilegeUse() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditAuthenticationPolicyChange() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditLogon() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditLogoff() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditProcessCreation() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditOtherSystemEvents() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditSystemIntegrity() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditAccountLockout() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditSpecialLogon() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditOtherLogonLogoffEvents() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditAuditPolicyChange() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditComputerAccountManagement() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditOtherAccountManagementEvents() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditSecurityStateChange() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditSecurityGroupManagement() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditIPsecDriver() == 'GOOD') ==1 : temp +=1
	if (AdvancedAuditPolicyConfiguration.AuditUserAccountManagement() == 'GOOD') ==1 : temp +=1
	if (FirewallDomainProfile.Applylocalconnectionsecurityrules() == 'GOOD') ==1 : temp +=1
	if (FirewallDomainProfile.Firewallstate() == 'GOOD') ==1 : temp +=1
	if (FirewallDomainProfile.Displayanotification() == 'GOOD') ==1 : temp +=1
	if (FirewallDomainProfile.Applylocalfirewallrules() == 'GOOD') ==1 : temp +=1
	if (FirewallDomainProfile.Inboundconnections() == 'GOOD') ==1 : temp +=1
	if (FirewallDomainProfile.LogSuccessfulConnections() == 'GOOD') ==1 : temp +=1
	if (FirewallDomainProfile.LoggingCustomizeSize() == 'GOOD') ==1 : temp +=1
	if (FirewallDomainProfile.LoggingCustomizeName() == 'GOOD') ==1 : temp +=1
	if (FirewallDomainProfile.Logdroppedpackets() == 'GOOD') ==1 : temp +=1
	if (FirewallDomainProfile.Outboundconnections() == 'GOOD') ==1 : temp +=1
	if (FirewallPrivateProfile.Applylocalconnectionsecurityrules() == 'GOOD') ==1 : temp +=1
	if (FirewallPrivateProfile.Firewallstate() == 'GOOD') ==1 : temp +=1
	if (FirewallPrivateProfile.Displayanotification() == 'GOOD') ==1 : temp +=1
	if (FirewallPrivateProfile.Applylocalfirewallrules() == 'GOOD') ==1 : temp +=1
	if (FirewallPrivateProfile.Inboundconnections() == 'GOOD') ==1 : temp +=1
	if (FirewallPrivateProfile.LogSuccessfulConnections() == 'GOOD') ==1 : temp +=1
	if (FirewallPrivateProfile.LoggingCustomizeSize() == 'GOOD') ==1 : temp +=1
	if (FirewallPrivateProfile.LoggingCustomizeName() == 'GOOD') ==1 : temp +=1
	if (FirewallPrivateProfile.Logdroppedpackets() == 'GOOD') ==1 : temp +=1
	if (FirewallPrivateProfile.Outboundconnections() == 'GOOD') ==1 : temp +=1
	if (FirewallPublicProfile.Applylocalconnectionsecurityrules() == 'GOOD') ==1 : temp +=1
	if (FirewallPublicProfile.Firewallstate() == 'GOOD') ==1 : temp +=1
	if (FirewallPublicProfile.Displayanotification() == 'GOOD') ==1 : temp +=1
	if (FirewallPublicProfile.Applylocalfirewallrules() == 'GOOD') ==1 : temp +=1
	if (FirewallPublicProfile.Inboundconnections() == 'GOOD') ==1 : temp +=1
	if (FirewallPublicProfile.LogSuccessfulConnections() == 'GOOD') ==1 : temp +=1
	if (FirewallPublicProfile.LoggingCustomizeSize() == 'GOOD') ==1 : temp +=1
	if (FirewallPublicProfile.LoggingCustomizeName() == 'GOOD') ==1 : temp +=1
	if (FirewallPublicProfile.Logdroppedpackets() == 'GOOD') ==1 : temp +=1
	if (FirewallPublicProfile.Outboundconnections() == 'GOOD') ==1 : temp +=1
	return temp
def notgood():
	notgood=0
	if (AccountPolicies.PasswordHistorySize() == 'NOT GOOD') ==1 : notgood +=1
	if (AccountPolicies.MaximumPasswordAge() == 'NOT GOOD') ==1 : notgood +=1
	if (AccountPolicies.MinimumPasswordAge() == 'NOT GOOD') ==1 : notgood +=1
	if (AccountPolicies.MinimumPasswordLength() == 'NOT GOOD') ==1 : notgood +=1
	if (AccountPolicies.PasswordComplexity() == 'NOT GOOD') ==1 : notgood +=1
	if (AccountPolicies.ClearTextPassword() == 'NOT GOOD') ==1 : notgood +=1
	if (AccountPolicies.LockoutDuration() == 'NOT GOOD') ==1 : notgood +=1
	if (AccountPolicies.LockoutBadCount() == 'NOT GOOD') ==1 : notgood +=1
	if (AccountPolicies.ResetLockoutCount() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeTrustedCredManAccessPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeNetworkLogonRight() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeTcbPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeIncreaseQuotaPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeInteractiveLogonRight() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeRemoteInteractiveLogonRight() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeBackupPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeSystemtimePrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeTimeZonePrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeCreatePagefilePrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeCreateTokenPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeCreateGlobalPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeCreatePermanentPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeCreateSymbolicLinkPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeIncreaseBasePriorityPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeDebugPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeDenyNetworkLogonRight() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeDenyBatchLogonRight() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeDenyServiceLogonRight() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeDenyInteractiveLogonRight() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeDenyRemoteInteractiveLogonRight() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeEnableDelegationPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeRemoteShutdownPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeAuditPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeImpersonatePrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeLoadDriverPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeLockMemoryPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeBatchLogonRight() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeServiceLogonRight() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeSecurityPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeRelabelPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeSystemEnvironmentPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeManageVolumePrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeSystemProfilePrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeProfileSingleProcessPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeAssignPrimaryTokenPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeRestorePrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeShutdownPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SeTakeOwnershipPrivilege() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.EnableAdminAccount() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.EnableGuestAccount() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.LimitBlankPasswordUse() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.NewAdministratorName() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.NewGuestName() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SCENoApplyLegacyAuditPolicy() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.crashonauditfail() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.AllocateDASD() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.AddPrinterDriver() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.RequireSignOrSeal() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SealSecureChannel() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SignSecureChannel() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.DisablePasswordChange() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.MaximumPasswordAge() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.RequireStrongKey() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.DontDisplayLastUserName() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.DisableCAD() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.LegalNoticeText() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.LegalNoticeCaption() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.CachedLogonsCount() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.PasswordExpiryWARNING() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.ScRemoveOption() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.RequireSecuritySignature() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.EnableSecuritySignature() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.EnablePlainTextPassword() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.autodisconnect() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.RequireSecuritySignatureServer() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.EnableSecuritySignatureServer() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.enableforcedlogoff() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SMBServerNameHardeningLevel() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.LSAAnonymousNameLookup() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.RestrictAnonymousSAM() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.RestrictAnonymous() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.disabledomaincreds() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.EveryoneIncludesAnonymous() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.NullSessionPipes() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.AllowedExactPaths() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.AllowedPaths() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.restrictnullsessaccess() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.NullSessionShares() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.ForceGuest() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.UseMachineId() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.allownullsessionfallback() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.AllowOnlineID() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.SupportedEncryptionTypes() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.NoLMHash() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.enableforcedlogoff1() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.LmCompatibilityLevel() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.LDAPClientIntegrity() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.NTLMMinClientSec() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.NTLMMinServerSec() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.ForceKeyProtection() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.ObCaseInsensitive() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.ProtectionMode() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.Optional() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.FilterAdministratorToken() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.EnableUIADesktopToggle() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.ConsentPromptBehaviorAdmin() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.ConsentPromptBehaviorUser() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.EnableInstallerDetection() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.EnableSecureUIAPaths() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.EnableLUA() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.PromptOnSecureDesktop() == 'NOT GOOD') ==1 : notgood +=1
	if (LocalPolicies.EnableVirtualization() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NCStdDomainUserSetLocation() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.SafeDllSearchMode() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.AllowBasic() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NtpServer() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.AllowIndexingEncryptedStoresOrItems() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.ExitOnMSICW() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.Nonamereleaseondemand() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NoBackgroundPolicy() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.fAllowUnsolicited() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.LocalAccountTokenFilterPolicy() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.Retention3() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.EnableUserControl() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.RDVPassphrase() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NoHeapTerminationOnCorruption() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.TurnonResponder() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.ScreenSaverGracePeriod() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.SafeForScripting() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DisablePasswordReveal() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NoPublishingWizard() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.RDVDiscoveryVolumeType() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.PasswordLength() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.RDVRecovery() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.MaxDisconnectionTime() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DisableQueryRemoteServer() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NoWebServices() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.ACSettingIndex1() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.TurnonMapperIO() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.fDisableLPT() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.MaxSize3() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.MaxSize2() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.MaxSize1() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.SpynetReporting() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.AllowRemoteRPC() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.UseLogonCredential() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.FDVAllowUserCert() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NoInternetOpenWith() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.PreventHandwritingDataSharing() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DisableIPSourceRouting() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.ScenarioExecutionEnabled() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DisableWebPnPDownload() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.EnableAuthEpResolution() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.EnableScriptBlockLogging() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DCSettingIndex1() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NoOnlinePrintsWizard() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.FDVRecoveryKey() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.EncryptionMethod() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.UseTPMPIN() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.AutoAdminLogon() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.EnableBDEWithNoTPM() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.RestrictRemoteClients() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.EMETInstall() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.SysSettings() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DeleteTempDirsOnExit() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.Peernet() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.Registrars() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.AllowDigest() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.OSRequireActiveDirectoryBackup() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.TurnOffSidebar() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NoAUAsDefaultShutdownOption() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NoDriveTypeAutoRun() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NoRegistration() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.OSManageDRA() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.AllowUnencryptedTraffic() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.PreventHandwritingErrorReports() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.FDVHideRecoveryPage() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.Defaults1() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NoAutoUpdate() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.UseAdvancedStartup() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.FDVDiscoveryVolumeType() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.UseTPMKeyPIN() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.FDVRecovery() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.FDVPassphrase() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.ASLR() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.EnumerateAdministrators() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DisableBkGndGroupPolicy() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.RDVEnforceUserCert() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.RDVActiveDirectoryBackup() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.RDVActiveDirectoryInfoToStore() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.Tcpmaxdataretransmissions() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.RDVRecoveryKey() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.PerSessionTempDir() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NoAUShutdownOption() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.Defaults() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DisableHTTPPrinting() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DenyDeviceClasses() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.AlwaysInstallElevated() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DisablePasswordSaving() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.WindowsErrorReporting() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.fPromptForPassword() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DisableIP6SourceRouting() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.CEIP() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NCAllowNetBridgeNLA() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.PreXPSP2ShellProtocolBehavior() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.AdmPwd() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.CEIPEnable() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DisableWcnUi() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.Tcpmaxdataretransmissions6() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.PwdExpirationProtection() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.FDVManageDRA() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.OSActiveDirectoryInfoToStore() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.PasswordAgeDays() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DEP() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NoAutorun() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.FDVRecoveryPassword() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.OSHideRecoveryPage() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NoAutoRebootWithLoggedOnUsers() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.TurnOffUserInstalledGadgets() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.EnableICMPRedirect() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DisableLocation() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.OSActiveDirectoryBackup() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.Retention1() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.Retention2() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.RDVManageDRA() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DCSettingIndex() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.UseTPMKey() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.PasswordComplexity() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DenyDeviceClasses1() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.AdmPwdEnabled() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.LogonType() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.RescheduleWaitTime() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.AllowUnencryptedTrafficService() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.UseTPM() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.EnableTranscripting() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.ACSettingIndex() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.RDVRecoveryPassword() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.FDVEnforceUserCert() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.UseEnhancedPin() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.AllowBasicService() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DenyDeviceClassesRetroactive() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NoGPOListChanges() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.fDisableCcm() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.RDVDenyWriteAccess() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DisableContentFileUpdates() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.MinEncryptionLevel() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.RDVDenyCrossOrg() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.OSRecoveryPassword() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.FDVRequireActiveDirectoryBackup() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.fDisablePNPRedir() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.OSRecoveryKey() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.ProcessCreationIncludeCmdLineEnabled() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.MaxSize() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.PerformRouterDiscovery() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DisableHomeGroup() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.RDVHideRecoveryPage() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NoDataExecutionPrevention() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.HardenedPaths() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.FDVActiveDirectoryBackup() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.MinimumPIN() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.RDVRequireActiveDirectoryBackup() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.fDenyTSConnections() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.fAllowToGetHelp() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.Disablesavepassword() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.MaxIdleTime() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.AllowRemoteShellAccess() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DisabledComponents() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NoAutoplayfornonVolume() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.WARNINGLevel() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.fDisableCdm() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.IE() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DisableRunAs() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.SEHOP() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.NtpClient() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.RDVAllowUserCert() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.KeepAliveTime() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.OSRecovery() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DefaultConsent() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.DisableEnclosureDownload() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.ScheduledInstallDay() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.FDVActiveDirectoryInfoToStore() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.fEncryptRPCTraffic() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesComputer.Retention() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesUser.NoImplicitFeedback() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesUser.ScreenSaveTimeOut() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesUser.ScreenSaverIsSecure() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesUser.ScanWithAntiVirus() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesUser.SaveZoneInformation() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesUser.AlwaysInstallElevated() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesUser.SCRNSAVE() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesUser.NoInplaceSharing() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesUser.PreventCodecDownload() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesUser.ScreenSaveActive() == 'NOT GOOD') ==1 : notgood +=1
	if (AdministrativeTemplatesUser.get_user_sid() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditApplicationGroupManagement() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditSecuritySystemExtension() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditCredentialValidation() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditSensitivePrivilegeUse() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditAuthenticationPolicyChange() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditLogon() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditLogoff() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditProcessCreation() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditOtherSystemEvents() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditSystemIntegrity() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditAccountLockout() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditSpecialLogon() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditOtherLogonLogoffEvents() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditAuditPolicyChange() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditComputerAccountManagement() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditOtherAccountManagementEvents() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditSecurityStateChange() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditSecurityGroupManagement() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditIPsecDriver() == 'NOT GOOD') ==1 : notgood +=1
	if (AdvancedAuditPolicyConfiguration.AuditUserAccountManagement() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallDomainProfile.Applylocalconnectionsecurityrules() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallDomainProfile.Firewallstate() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallDomainProfile.Displayanotification() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallDomainProfile.Applylocalfirewallrules() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallDomainProfile.Inboundconnections() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallDomainProfile.LogSuccessfulConnections() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallDomainProfile.LoggingCustomizeSize() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallDomainProfile.LoggingCustomizeName() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallDomainProfile.Logdroppedpackets() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallDomainProfile.Outboundconnections() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPrivateProfile.Applylocalconnectionsecurityrules() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPrivateProfile.Firewallstate() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPrivateProfile.Displayanotification() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPrivateProfile.Applylocalfirewallrules() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPrivateProfile.Inboundconnections() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPrivateProfile.LogSuccessfulConnections() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPrivateProfile.LoggingCustomizeSize() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPrivateProfile.LoggingCustomizeName() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPrivateProfile.Logdroppedpackets() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPrivateProfile.Outboundconnections() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPublicProfile.Applylocalconnectionsecurityrules() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPublicProfile.Firewallstate() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPublicProfile.Displayanotification() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPublicProfile.Applylocalfirewallrules() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPublicProfile.Inboundconnections() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPublicProfile.LogSuccessfulConnections() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPublicProfile.LoggingCustomizeSize() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPublicProfile.LoggingCustomizeName() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPublicProfile.Logdroppedpackets() == 'NOT GOOD') ==1 : notgood +=1
	if (FirewallPublicProfile.Outboundconnections() == 'NOT GOOD') ==1 : notgood +=1
	return notgood
