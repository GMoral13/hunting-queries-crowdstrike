Show me all CreateService events

```
#event_simpleName=CreateService
| table([aid, ServiceDisplayName, ServiceImagePath, ClientComputerName, RemoteAddressIP4, RemoteAddressIP6 ], limit=1000)
```