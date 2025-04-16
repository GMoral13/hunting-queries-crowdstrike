User Account Added to Local Admin Group

```
#event_simpleName=UserAccountAddedToGroup
| parseInt(GroupRid, as="GroupRid", radix="16", endian="big")
| parseInt(UserRid, as="UserRid", radix="16", endian="big")
| UserSid:=format(format="%s-%s", field=[DomainSid, UserRid])
| groupBy([aid, UserSid], function=([selectFromMin(field="@timestamp", include=[RpcClientProcessId]), collect([ComputerName, DomainSid, UserRid])]))
| ContextTimeStamp:=ContextTimeStamp*1000
| ContextTimeStamp:=formatTime(format="%F %T", field="ContextTimeStamp")
| join(query={$falcon/investigate:usersid_username_win()}, field=[UserSid], include=UserName)
// Cambiar la rootURL con la cloud necesaria
| rootURL  := "https://falcon.eu-1.crowdstrike.com/"
| format("[Responsible Process](%sgraphs/process-explorer/tree?id=pid:%s:%s)", field=["rootURL", "aid", "RpcClientProcessId"], as="Process Explorer") 
| drop([rootURL, RpcClientProcessId])
```