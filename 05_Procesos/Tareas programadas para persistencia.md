Búsqueda de tareas programadas que pueden usarse para persistencia:

```
#event_simpleName = ProcessRollup2 FileName="schtasks.exe" CommandLine="*run*"
| groupBy([CommandLine])
```