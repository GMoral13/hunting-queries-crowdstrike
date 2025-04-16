Buscamos cualquier descarga realizada con esta herramienta:

```
#event_simpleName=ProcessRollup2
| ImageFileName=/\\powershell\.exe/i CommandLine=/(Invoke-WebRequest|Net\.WebClient|Start-BitsTransfer)/i
| join({#event_simpleName=UserIdentity | groupBy([aid, AuthenticationId, UserName], limit=max)}, field=AuthenticationId, include=UserName)
| table([aid, UserName, ImageFileName, CommandLine], limit=1000)
```