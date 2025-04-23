Show me any BITS transfers (can be used to transfer malicious binaries)

```
#event_simpleName=ProcessRollup2 FileName=bitsadmin.exe (CommandLine=*/Transfer* OR CommandLine=*/Addfile*)
```

```
#event_simpleName=ProcessRollup2 ImageFileName=/\\bitsadmin.exe/i CommandHistory=/(Transfer|Addfile)/i
| join({#event_simpleName=UserIdentity | groupby([aid, AuthenticationId, UserName])}, field=AuthenticationId, include=UserName)
| groupby([aid, CommandHistory], function=stats([collect(UserName), collect(ImageFileName), collect(SHA256HashData)]))
```