Simple check for excessive single character variables in powershell

```
#event_simpleName = "*ProcessRollup*" and CommandLine = /powershell/i
| regex(field=CommandLine, regex="(?<single_vars>\$[a-zA-Z0-9])\W", repeat=true, limit=500)
| groupby([ComputerName, ParentBaseFileName, CommandLine], function=([
    collect([single_vars]),
    count(single_vars, distinct=true, as=unique_vars)
    ])
  )
| test(unique_vars > 1)
| replace(field=CommandLine, regex="\\\\u000(a|d)", with="\n")
| replace(field=CommandLine, regex=";", with="\n")
| replace(field=CommandLine, regex="^$\n", with="")
```