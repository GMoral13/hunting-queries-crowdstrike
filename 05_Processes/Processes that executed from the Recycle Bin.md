Show me a list of processes that executed from the Recycle Bin

To see a list of executables running from the Recycle Bin, Falcon provides you a premade report on the Events Search page under Investigate > Hunt > Executables running from Recycle Bin. With Falcon LTR, you can run the following query:

```
#event_simpleName=ProcessRollup2  aid=?aid ImageFileName=/\$Recycle\.Bin/
| groupby(aid, function=stats([collect(SHA256HashData), collect(ImageFileName)]))
```