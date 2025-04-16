RFM Hosts

```
#repo=base_sensor #event_simpleName=SensorHeartbeat (event_platform=Win OR event_platform=Lin)
| groupBy([aid], limit=max, function=selectLast([@timestamp, ComputerName, aid, ConfigIDBuild, SensorStateBitMap, event_platform]))
| SensorStateBitMap=2
```