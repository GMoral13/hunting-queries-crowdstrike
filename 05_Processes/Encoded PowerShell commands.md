Show me any encoded PowerShell commands

```
#event_simpleName=ProcessRollup2 ImageFileName=/\\powershell.exe/i CommandLine=/(-enc|encoded)/i
| join({#event_simpleName=UserIdentity | groupby([aid, AuthenticationId, UserName])}, field=AuthenticationId, include=UserName)
| table([aid, UserName, ImageFileName, CommandLine])
```