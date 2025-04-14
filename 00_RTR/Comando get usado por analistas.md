```
#repo="detections" ExternalApiType=/Remote/
| array:regex("Commands[]",regex="get")
| concatArray("Commands", separator="; ", as=Commands)
| Commands=*
| groupBy([UserName, AgentIdString], function=([collect([Commands])]))
| groupBy([UserName], function=([count(AgentIdString, as=SystemsAccssed), collect([Commands])]))
```
