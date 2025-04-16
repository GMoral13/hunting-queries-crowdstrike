Para ver archivos escritos en un USB externo

```
#event_simpleName=*FileWritten AND IsOnRemovableDisk = 1
| table([ComputerName,UserName,FileName,FilePath])
```