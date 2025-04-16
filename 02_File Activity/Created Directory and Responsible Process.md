This query can be used for:

-   Searching for a specific created directory by its name (DirectoryName)
-   Searching for all directories created by a particular process (e.g., powershell.exe) using the process name (ProcessName).
-   Searching for all directories created on a specific computer (ComputerName).

```
(#event_simpleName=ProcessRollup2 FileName=?ProcessName) or (#event_simpleName="DirectoryCreate" FileName=?DirectoryName)
| ComputerName=?ComputerName
| case {
    #event_simpleName="DirectoryCreate" | CreatedDirTimestamp:=ContextTimeStamp*1000 | CreatedDirTimestamp:=formatTime(format="%F %T", field=CreatedDirTimestamp) | CreatedDirectories:=format(format="%s (%s)", field=[TargetFileName, CreatedDirTimestamp]);
    #event_simpleName="ProcessRollup2" | rename(field="CommandLine", as="ProcessCommandLine");
}
| falconPID:=TargetProcessId | falconPID:=ContextProcessId
| selfJoinFilter([aid, falconPID], where=[{#event_simpleName=ProcessRollup2}, {#event_simpleName="DirectoryCreate"}], prefilter=true)
| groupBy([aid, ComputerName, falconPID], function=([collect([ProcessCommandLine, CreatedDirectories])]))
| ProcessCommandLine=* CreatedDirectories=*
| drop([falconPID])
```
