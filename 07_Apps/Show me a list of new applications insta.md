Show me a list of new applications installed on a system

```
#event_simpleName = "InstalledApplication"
| AppName=?ApplicationName
| sort(timestamp, order=asc)
| timestamp:=formatTime(field=timestamp, format="%Y/%m/%d %H:%M:%S")
| case {  
   AppType=0 | typeDesc:="ALL";  
   AppType=1 | typeDesc:="UNINSTALL";  
   AppType=2 | typeDesc:="CLSID"; 
   AppType=3 | typeDesc:="CUSTOM";
   AppType=4 | typeDesc:="APPLE_BUNDLE"; 
   *;  
}
| case {  
   UpdateFlag=0 | updFlag:="INVALID";  
   UpdateFlag=1 | updFlag:="ENUMERATION";
   UpdateFlag=2 | updFlag:="REMOVED";
   UpdateFlag=3 | updFlag:="ADDED";
   UpdateFlag=4 | updFlag:="OBSOLETE";
   UpdateFlag=5 | updFlag:="REVISED";
   *;  
}
| select([timestamp,ComputerName,typeDesc,AppName,AppVendor,AppVersion,updFlag])
```