RFM Hosts

```
#event_simpleName=OsVersionInfo
| groupBy(aid, function=selectLast([@timestamp,RFMState,aid,ComputerName,ProductName,OSVersionString]))
| RFMState=1
| OSVersionString match{
 *=> ProductName:=OSVersionString ;}
| select([@timestamp,aid,ComputerName,ProductName])
```

```
#repo=base_sensor #event_simpleName=SensorHeartbeat (event_platform=Win OR event_platform=Lin)
| groupBy([aid], limit=max, function=selectLast([@timestamp, ComputerName, aid, ConfigIDBuild, SensorStateBitMap, event_platform]))
| SensorStateBitMap=2
```