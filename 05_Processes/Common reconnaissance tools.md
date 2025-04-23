Show me any instances of common reconnaissance tools on a host

```
#event_simpleName=ProcessRollup2 (FileName=net.exe OR FileName=ipconfig.exe OR FileName=whoami.exe OR FileName=quser.exe OR FileName=ping.exe OR FileName=netstat.exe OR FileName=tasklist.exe OR FileName=Hostname.exe OR FileName=at.exe)
| groupBy([ComputerName, UserName, FileName, CommandLine])
```

```
event_simpleName=ProcessRollup2 aid=?aid
| ImageFileName = /(net|ipconfig|whoami|quser|ping|netstat|tasklist|hostname|at)\.exe$/
| join({#event_simpleName=UserIdentity aid=?aid | groupby([aid, AuthenticationId, UserName])}, field=AuthenticationId, include=UserName)
| table([aid, UserName, ImageFileName, CommandLine])
```