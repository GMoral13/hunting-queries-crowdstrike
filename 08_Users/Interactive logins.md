Interactive logins

```
"#event_simpleName" = UserLogon
| in(LogonType, values=[1, 2])
| ComputerName = ?ComputerName
| table([@timestamp, aip, LocalIP, UserName, UserSid, LogonDomain, LogonServer, event_platform], limit=20000)
| sort(@timestamp, order = desc)
```