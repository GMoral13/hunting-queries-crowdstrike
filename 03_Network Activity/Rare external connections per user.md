Rare external connections per user

```
#event_simpleName=NetworkConnectIP4
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "127.0.0.0/8"])
| join({ProcessRollup2}, field=[ContextProcessId], key=TargetProcessId, include=[FileName, UserName, ImageFileName, RemoteAddressIP4, RemotePort, CommandLine], mode=left)
| groupBy(UserName, function=collect([FileName, UserName, ImageFileName, RemoteIP, RPort, CommandLine]))
| sort([_count], order=asc)
```