Show me a list of processes executing from browser file paths
Processes typically shouldn’t be running from these locations:

```
aid=?aid (#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2) AND (ImageFileName=/.*\\AppData\\Local\\Microsoft\\Windows\\Temporary.Internet.Files\\\w+\.exe|.*\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\\w+\.exe|.*\\AppData\\Local\\Google\\Chrome\\\w+\.exe|.*\\Downloads\\\w+\.exe/i)
| regex(regex="(?<FileName>[^\\/|\\\\]*)$",field=ImageFileName)
| groupBy([aid, ImageFileName, FileName, SHA256HashData])
```