Ejecuciones de powershell para infectar los equipos, cualquier comando de encriptación existente del mismo:

```
#event_simpleName=ProcessRollup2
| ImageFileName=/\\powershell\.exe/i CommandLine=/\s-[e^]{1,2}[ncodema^]+\s/i
| join({#event_simpleName=UserIdentity | groupBy([aid, AuthenticationId, UserName], limit=max)}, field=AuthenticationId, include=UserName)
| table([aid, UserName, ImageFileName, CommandLine], limit=1000)
```