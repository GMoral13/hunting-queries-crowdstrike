Search if any fields from a select set of fields, contain a select set of values

```
#event_simpleName=ProcessRollup2 OR #event_simpleName=NetworkConnectIP4
| case {
    #event_simpleName=ProcessRollup2    | CommandLine=/(192\.168\.1\.1|127\.0\.0\.1)/ | matchingString:=CommandLine;
    #event_simpleName=NetworkConnectIP4 | RemoteAddressIP4=/(192\.168\.1\.1|127\.0\.0\.1)/ | matchingString:=RemoteAddressIP4;
}
| table([@timestamp, aid, ComputerName, #event_simpleName, matchingString], limit=1000)
```