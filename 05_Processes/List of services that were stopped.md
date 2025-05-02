Show me a list of services that were stopped and on which hosts

```
#event_simpleName=/ProcessRollup2/
| join({#event_simpleName=ServiceStopped} key=TargetProcessId, field=TargetProcessId)
```