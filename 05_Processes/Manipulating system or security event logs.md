Manipulating system or security event logs

```
"#event_simpleName" = EventLogCleared
| table([@timestamp, aid, ComputerName, UserName, FileName, FilePath])
```