Show me binaries running as a service that do not originate from “System32”

```
#event_simpleName=ServiceStarted ImageFileName!="*\\System32\\*"
| groupBy([aid, ServiceDisplayName, ImageFileName, CommandLine, ClientComputerName, RemoteAddressIP4, RemoteAddressIP6])
```