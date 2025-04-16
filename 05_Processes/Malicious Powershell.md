Malicious Powershell

```
#event_simpleName=ProcessRollup2 ParentBaseFileName=explorer.exe
|in(field="FileName",ignoreCase=true, values=[*powershell*,*mshta*])
|in(field="CommandLine",ignoreCase=true, values=[*iex*,*irm*,*http*,*curl*,*datetime*])
| case {
 TargetProcessId=* | process_tree := format("[PT](/graphs/process-explorer/tree?_cid=%s&id=pid:%s:%s&investigate=true&pid=pid:%s:%s)",field=["#repo.cid","aid","TargetProcessId","aid","TargetProcessId"]);
 *
}
|groupBy([process_tree,@timestamp,ComputerName,ParentBaseFileName,FileName,CommandLine])
```