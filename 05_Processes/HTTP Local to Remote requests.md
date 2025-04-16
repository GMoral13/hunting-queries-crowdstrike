Peticiones HTTP Local to Remote

```
#event_simpleName="HttpResponse"
| groupBy([@timestamp, ComputerName, RemoteAddressIP4, CommandLine])
| RemoteAddressIP4:=format("[%s](https://www.abuseipdb.com/check/%s)", field=[RemoteAddressIP4, RemoteAddressIP4])
| drop([_count])
```