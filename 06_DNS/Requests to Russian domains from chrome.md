Peticiones a dominios rusos desde chrome

```
(#event_simpleName=ProcessRollup2 event_platform=Win ImageFileName=/\\chrome\.exe$/i) OR (#event_simpleName=DnsRequest DomainName=/\.ru$/ event_platform=Win)
| falconPID:=TargetProcessId | falconPID:=ContextProcessId
| selfJoinFilter([aid, falconPID], where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName=DnsRequest}], prefilter=true)
| groupBy([aid, falconPID], function=([collect([DomainName, UserName, ComputerName, ImageFileName, CommandLine])]))
| DomainName=* ImageFileName=*
```