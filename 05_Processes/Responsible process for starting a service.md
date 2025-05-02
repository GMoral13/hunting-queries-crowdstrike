Show me the responsible process for starting a service

```
#event_simpleName=ProcessRollup2
| join({#event_simpleName=ServiceStarted}, key=RpcClientProcessId, field=SourceProcessId, include=[ServiceDisplayName])
| table([aid, ImageFileName, ServiceDisplayName], limit=1000)
```