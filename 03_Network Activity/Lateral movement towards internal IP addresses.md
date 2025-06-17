Lateral movement towards internal IP addresss

```
event_platform=Lin 
| in(field="#event_simpleName", values=[ProcessRollup2,NetworkConnectIP4])
| in(field="ComputerName", values=[COMPUTER1])
| case {
  #event_simpleName=ProcessRollup2 CommandLine=/\s+(ssh|scp|rsync|curl|wget|python|nc|ncat|socat)\s+/;
  #event_simpleName=NetworkConnectIP4 | cidr(RemoteAddressIP4, subnet=["224.0.0.0/4", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1/32", "169.254.0.0/16", "0.0.0.0/32"]);
}
| table([@timestamp, aid, ComputerName, UID, UserName, ParentBaseFileName, FileName, CommandLine, RemoteAddressIP4, LocalAddressIP4], sortby=@timestamp, order=desc, limit=200000)
| default(value="-", field=[UID, UserName, ParentBaseFileName, FileName, CommandLine, RemoteAddressIP4, LocalAddressIP4])
```