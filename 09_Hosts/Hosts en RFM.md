RFM Hosts

```
#event_simpleName=OsVersionInfo
| groupBy(aid, function=selectLast([@timestamp,RFMState,aid,ComputerName,ProductName,OSVersionString]))
| RFMState=1
| OSVersionString match{
 *=> ProductName:=OSVersionString ;}
| select([@timestamp,aid,ComputerName,ProductName])
```