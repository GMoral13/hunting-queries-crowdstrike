Show files written to removable USB disk

```
(#event_simpleName=DcUsbDeviceConnected) OR (#event_simpleName=*FileWritten IsOnRemovableDisk=1)
| DeviceId:=DeviceInstanceId
| DeviceId:=DiskParentDeviceInstanceId
| selfJoinFilter(field=[DeviceId, aid], where=[{*FileWritten OR #event_simpleName=DcUsbDeviceConnected}, {IsOnRemovableDisk=1}])
| ContextTimeStamp :=parseTimeStamp(field=ContextTimeStamp, format=seconds)
| ReadableEventTime:= formatTime("%Y-%m-%dT%H:%M:%S.%L", field=ContextTimeStamp, timezone="Zulu")
| groupBy([aid, DeviceId], function=([collect([ComputerName, DevicePropertyClassName, DeviceManufacturer, DeviceProduct, ReadableEventTime, ContextTimeStamp, FileName])]))
```