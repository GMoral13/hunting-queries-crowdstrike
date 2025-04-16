A System Has Three Or more Failed Interactive Login Attempts Followed By A Successful Interactive Login

```
// Get successful and failed user logon events
(#event_simpleName=UserLogon OR #event_simpleName=UserLogonFailed2) UserName!=/^(DWM|UMFD)-\d+$/
// Restrict to LogonType 2 and 10
| in(field="LogonType", values=[2, 10])
// Aggregate by key fields Agent ID and timestamp; collect the event name
| groupBy([aid, @timestamp], function=([collect([event_platform, #event_simpleName, UserName], multival=false), selectLast([ComputerName])]), limit=max)
// Use slidingTimeWindow to look for 3 or more failed user login events on a single Agent ID followed by a successful login event in a 10 minute window
| groupBy(
   aid,
   function=slidingTimeWindow(
       [{#event_simpleName=UserLogonFailed2 | count(as=FailedLogonAttempts)}, {collect([UserName]) | rename(field="UserName", as="FailedLogonAccounts")}],
       span=10m
   ), limit=max
 )
// Rename fields
| rename([[UserName,LastSuccessfulLogon],[@timestamp,LastLogonTime]])
// This is the FailedLogonAttempts threshold
| FailedLogonAttempts >= 3
// This is the event that needs to occur after the threshold is met
| #event_simpleName=UserLogon
// Convert LastLogonTime to Human Readable format
| LastLogonTime:=formatTime(format="%F %T.%L %Z", field="LastLogonTime")
// User Search
| rootURL  := "https://falcon.eu-1.crowdstrike.com/"
| format("[Scope User](%sinvestigate/dashboards/user-search?isLive=false&sharedTime=true&start=7d&user=%s)", field=["rootURL", "LastSuccessfulLogon"], as="User Search")
// Asset Graph
| format("[Scope Asset](%sasset-details/managed/%s)", field=["rootURL", "aid"], as="Asset Graph")
// Adding description
| Description:=format(format="User %s logged on to system %s (Agent ID: %s) successfully after %s failed logon attempts were observed on the host.", field=[LastSuccessfulLogon, ComputerName, aid, FailedLogonAttempts])
// Final field organization
| groupBy([aid, ComputerName, event_platform, LastSuccessfulLogon, LastLogonTime, FailedLogonAccounts, FailedLogonAttempts, "User Search", "Asset Graph", Description], function=[], limit=max)
```