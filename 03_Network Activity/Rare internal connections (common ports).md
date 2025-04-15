Rare internal connections (common ports)

```
#event_simpleName=NetworkConnectIP4
|in(field="RemotePort", values=[137, 139, 389, 3389, 445])
| join({#event_simpleName=ProcessRollup2}, field=[ContextProcessId], key=TargetProcessId, include=[UserName, ComputerName, ImageFileName, RemoteAddressIP4, RemotePort], mode=left)
| groupBy(ComputerName, function=collect([FileName, UserName, ImageFileName, RemoteAddressIP4, RemotePort]))
| sort([_count], order=asc)
```