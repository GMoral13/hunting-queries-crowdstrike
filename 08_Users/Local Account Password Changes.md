Local Account Password Changes

```
#event_simpleName=UserLogon PasswordLastSet!=""
| UID:=concat(UID, UserSid)
| groupBy([cid, aid, UID, UserName], function=([selectLast([PasswordLastSet])]), limit=max)
| PasswordLastSet:=PasswordLastSet*1000
| Ago:=now()-PasswordLastSet
| sort(Ago, order=desc, limit=20000)
| formatDuration("Ago", precision=2)
| PasswordLastSet:=formatTime(format="%F %T", field="PasswordLastSet")
```