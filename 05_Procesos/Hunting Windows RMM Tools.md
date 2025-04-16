Hunting Windows RMM Tools

Se necesita subir el archivo "rmm_list.csv" a /investigate/search/lookup-files (apartado de NG-SIEM)

```
// Get all Windows process execution events
| #event_simpleName=ProcessRollup2 event_platform=Win
// Check to see if FileName value matches the value or a known RMM tools as specified by our lookup file
| match(file="rmm_list.csv", field=[FileName], column=rmm_binary, ignoreCase=true)
// Do some light formatting
| regex("(?<short_binary_name>\w+)\.exe", field=FileName)
| short_binary_name:=lower("short_binary_name")
| rmm_binary:=lower(rmm_binary)
// Aggregate by RMM program name
| groupBy([rmm_program], function=([
    collect([rmm_binary]),
    collect([short_binary_name], separator="|"),  
    count(FileName, distinct=true, as=FileCount),
    count(aid, distinct=true, as=EndpointCount),
    count(aid, as=ExecutionCount)
]))
// Create case statement to display what Custom IOA regex will look like
| case{
    FileCount>1 | ImageFileName_Regex:=format(format=".*\\\\(%s)\\.exe", field=[short_binary_name]);
    FileCount=1 | ImageFileName_Regex:=format(format=".*\\\\%s\\.exe", field=[short_binary_name]);
}
// More formatting
| description:=format(format="Unexpected use of %s observed. Please investigate.", field=[rmm_program])
| rename([[rmm_program,RuleName],[rmm_binary,BinaryCoverage]])
| table([RuleName, EndpointCount, ExecutionCount, description, ImageFileName_Regex, BinaryCoverage], sortby=ExecutionCount, order=desc)
```