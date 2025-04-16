This query can be used to correlate USB mount events with the potentially responsible user. It can be helpful in identifying the user who plugged in a malicious USB in a shared workstation.

```
(#event_simpleName=UserLogon OR #event_simpleName=RemovableMediaVolumeMounted)
| ComputerName=?ComputerName
| case {
     #event_simpleName=RemovableMediaVolumeMounted | removeableMediaMountTime:=ContextTimeStamp |  removeableMediaMountTime:=removeableMediaMountTime*1000 | removeableMediaMountTime:=formatTime(format="%F %T", field="removeableMediaMountTime") |  default(value="No Label", field=VolumeLabel, replaceEmpty=true) | USBMounts:=format(format="%s (%s) - DeviceId: %s on %s", field=[VolumeLabel, VolumeDriveLetter, DiskParentDeviceInstanceId,removeableMediaMountTime]);
     #event_simpleName=UserLogon | UserName =~ not in(values=["SYSTEM", "UMFD-*", "DWM-*", "*$", "*SERVICE*"]) | LogonTime:=ContextTimeStamp*1000 | LogonTime:=formatTime(format="%F %T", field=LogonTime) | UserLogons:=format(format="%s on %s", field=[UserName, LogonTime]);
}
| groupBy([aid, ComputerName], function=[collect([USBMounts, UserLogons])])
| USBMounts=* 
| LogonTime:=LogonTime*1000 | LogonTime:=formatTime(format="%F %T", field="LogonTime") 
```
