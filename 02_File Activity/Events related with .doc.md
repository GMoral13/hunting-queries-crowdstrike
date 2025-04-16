Eventos relacionados con escritura de ficheros .doc

```
#event_simpleName=/FileWritten$/ FileName=/doc/i
| FilePath=/\\Device\\HarddiskVolume\d+(?<ShortFilePath>.+$)/
| groupBy([ComputerName, FileName, ShortFilePath])
```