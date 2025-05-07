Hunting Fake CAPTCHA Artifacts in Windows

```
| #event_simpleName=ProcessRollup2 AND ParentBaseFileName = explorer.exe AND  LinkName!="*" 
| WindowFlags=1025
//for variations that use GUI select 2, for variations that use Native/CUI select 3
| ImageSubsystem = 2
//for variations that use mshta.exe
| FileName = mshta.exe
| CmdLength:=length("CommandLine")
// Can raise or loweer this threshold
| test(CmdLength>50)
// Checks for presense of "http" or "https"
| CommandLine=/https?/iF
| table([@timestamp, aid, ComputerName, UserName, UserSid, FileName, CmdLength, CommandLine], sortby=CmdLength, order=desc, limit=500)
```