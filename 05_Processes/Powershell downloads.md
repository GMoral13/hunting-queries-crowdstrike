Show me any powershell.exe downloads

```
#event_simpleName=ProcessRollup2 ImageFileName=/\\powershell.exe/i CommandLine=/(Invoke-WebRequests|Net\.WebClient|Start-BitsTransfer)/i
| join({#event_simpleName=UserIdentity | groupby([aid, AuthenticationId, UserName])}, field=AuthenticationId, include=UserName)
| table([aid, UserName, ImageFileName, CommandLine])
```