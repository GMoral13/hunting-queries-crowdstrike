Stack command line activity for common attacker binaries

```
#event_simpleName=ProcessRollup2
| in(CommandLine, values=["*\\arp.exe*", "at *", "*\\at.exe*", "bitsadmin*", "*\\bitsadmin.exe*", "*csvde.exe*", "dsquery*", "*\\dsquery.exe*", "*\\ftp.exe*", "*\\makecab.exe*", "*nbtstat*", "net *", "*\\net.exe*", "*\\net1.exe*", "netsh*", "*\\netsh.exe*", "netstat *", "*\\netstat.exe*", "*nslookup*", "ping *", "*\\ping.exe*", "*quser.exe*", "*\\reg.exe*", "*\\regsvr32.exe*", "route *", "*\\route.exe*", "sc*", "*\\sc.exe*", "schtasks*", "*\\schtasks.exe*", "systeminfo*", "taskkill*", "*\\taskkill.exe*", "tasklist*", "*\\tasklist.exe*", "*wevtutil*", "whoami*", "*\\whoami.exe*", "*\\xcopy.exe", "wmic *", "*\\wmic.exe*", "psexec*", "*\\psexec.exe*", "*\\psexesvc.exe*", "powershell.exe*", "*\\powershell.exe*", "*\\cmd.exe*", "cmd*", "cmd.exe*"])
| !in(field="CommandLine", values=["*powershell.exe*\\CCM\\*", "\"C:\\Windows\\system32\\SearchFilterHost.exe\"*", "\"C:\Windows\system32\SearchProtocolHost.exe\"*", "\"C:\\Windows\\system32\\makecab.exe\" C:\\Windows\\Logs\\CBS\\*", "\"C:\\Windows\\CCM\\*", "\\??\\C:\\Windows\\system32\\conhost.exe\"*", "rundll32 C:\\Windows\\system32\\spool\\DRIVERS\\*", "taskeng.exe\{*", "microsoftmonitoring agent", "system center operations manager"])
| groupBy([UserName, ComputerName], function=([collect([CommandLine])]))
| sort([_count], order=desc)
```