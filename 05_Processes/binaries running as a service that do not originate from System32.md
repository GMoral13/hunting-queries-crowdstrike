Show me binaries running as a service that do not originate from “System32”
If hunting for anomalous activity, look for services that do not originate from “Windows\System32” location. Remember to escape the directory backslashes (“\”) with another backslash.

```
#event_simpleName=ServiceStarted ImageFileName!="*\\System32\\*"
| groupBy([aid, ServiceDisplayName, ImageFileName, CommandLine, ClientComputerName, RemoteAddressIP4, RemoteAddressIP6])
```

```
#event_simpleName=ServiceStarted ImageFileName=/\\svchost.exe/i ImageFileName!=/\\System32\\/i 
| table([aid, ServiceDisplayName, ImageFileName, CommandLine, ClientComputerName, RemoteAddressIP4, RemoteAddressIP6], limit=1000)
```