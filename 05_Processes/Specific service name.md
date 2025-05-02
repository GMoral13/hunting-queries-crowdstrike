Show me a specific service name
In the table fields, the ContextTimeStamp will provide the system time of event creation which will be useful when correlating with the time frame of interest. The RemoteAddressIP4 will provide the IP address of the remote machine that initiated the request (origin) and ClientComputerName will provide the NetBios name of the remote machine.

```
#event_simpleName=ServiceStarted ServiceDisplayName=?service
| table([aid, ServiceDisplayName, ImageFileName, CommandLine, ClientComputerName, RemoteAddressIP4, RemoteAddressIP6], limit=1000)
```