Busca nombres de archivo que terminen en html o txt o pdf o doc o ppt pero que tengan extensión .zip

```
#repo=base_sensor  #event_simpleName=ZipFileWritten
FileName=/(txt|pdf|doc|docm|ppt|html)\.zip/i
| groupBy([#event_simpleName, @timestampt, FileName],function =(count(FileName, as=FileNameCount)))
```