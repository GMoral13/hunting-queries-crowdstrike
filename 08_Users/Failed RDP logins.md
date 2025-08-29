Logins fallidos por RDP

```
#event_simpleName=UserLogonFailed2 RemoteAddressIP4=* LogonType=10
| !cidr(RemoteAddressIP4, subnet=["224.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/32", "169.254.0.0/16", "0.0.0.0/32"])
| groupBy([RemoteAddressIP4, UserName], limit=max)
| ipLocation(RemoteAddressIP4)
| asn(RemoteAddressIP4)
| reverseDns(RemoteAddressIP4)
| default(value="-", field=[RemoteAddressIP4.asn, RemoteAddressIP4.city, RemoteAddressIP4.country, RemoteAddressIP4.state, RemoteAddressIP4.org, hostname])
| groupBy([RemoteAddressIP4, UserName, hostname, _count, RemoteAddressIP4.asn, RemoteAddressIP4.org, RemoteAddressIP4.country, RemoteAddressIP4.state, RemoteAddressIP4.city], function=[], limit=max)
```