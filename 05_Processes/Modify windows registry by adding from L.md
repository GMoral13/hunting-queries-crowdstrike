 Modify windows registry by adding from LDAP user

 ```
#repo=base_sensor FileName="reg.exe" CommandLine="* add *" 
| in(#event_simpleName, values=[ProcessRollup2, SyntheticProcessRollup2])
| regex("(?<LDAP_User>\\\\Users\\\\([^\\\\]+)\\\\Default\\\\)", field=CommandLine, strict=false)
| LDAP_User:=replace(regex="\\\\Users\\\\|\\\\Default\\\\", field=LDAP_User)
| LDAP_User=?LDAP_User
| LocalIP=?LocalIP
| ComputerName=?ComputerName
| table([@timestamp, ComputerName, UserName, LDAP_User, LocalIP, commandLine], limit=20000)
| sort(@timestamp, order=desc, limit=20000)
 ```

 ```
#repo=base_sensor FileName="reg.exe" CommandLine="* add *" 
| in(#event_simpleName, values=[ProcessRollup2, SyntheticProcessRollup2])
| event_platform match {
    "Win" => username := UserName;
    * => username := UserPrincipal;
}
| regex("(?<LDAP_User>\\\\Users\\\\([^\\\\]+)\\\\Default\\\\)", field=CommandLine, strict=false)
| LDAP_User:=replace(regex="\\\\Users\\\\|\\\\Default\\\\", field=LDAP_User)
| ProcessStartTime := parseTimestamp(field=ProcessStartTime, format=seconds)
| processStartTime := formatTime("%FT%TZ", field=ProcessStartTime)
| ContextTimeStamp := parseTimestamp(field=ContextTimeStamp, format=seconds) 
| contextTimestamp := formatTime("%FT%TZ", field=ContextTimeStamp) 
| computerName := rename(ComputerName) 
| filename := rename(FileName) 
| UserName=?UserName
| LDAP_User=?LDAP_User
| LocalIP=?LocalIP
| ComputerName=?ComputerName
| default(field=username, value="--", replaceEmpty=true) 
| table([@timestamp, ComputerName, UserName, LDAP_User, LocalIP, commandLine], limit=20000)
| sort(@timestamp, order=desc, limit=20000)
 ```