Show me a list of processes executing from User Profile file paths
Processes generally shouldn’t be executing from user spaces. These paths cover spaces that are considered to be User Paths.

```
(#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2)
| ImageFileName = /\\Desktop\\/ OR ImageFileName=/\\AppData(\\Local|\\Local\\Temp|\\Roaming)?\\/
| join({#event_simpleName=UserIdentity | groupby([aid, AuthenticationId, UserName])}, field=AuthenticationId, include=UserName)
| table([aid, UserName, ImageFileName, SHA256HashData])
```