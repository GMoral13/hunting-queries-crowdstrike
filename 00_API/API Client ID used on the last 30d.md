API Client ID usados en los últimos 30 días:

```
setTimeInterval(start="30d")
| #repo=detections EventType=Event_ExternalApiEvent ServiceName=api_request Attributes.APIClientID=* Attributes.request_path="/detects/*"
| groupBy(
    [Attributes.request_method, Attributes.request_path]
    , limit=max
    , function=[
        collect([Attributes.APIClientID, Attributes.user_ip, Attributes.user_agent])
        ,selectLast(@timestamp)
        ,count(as=RequestCount)
    ]
)
| rename([
      [ Attributes.request_method , RequestMethod   ]
    , [ Attributes.request_path   , RequestPath     ]
    , [ Attributes.APIClientID    , APIClientID     ]
    , [ Attributes.user_ip        , IPAddress       ]
    , [ @timestamp                , LastRequestTime ]
    , [ Attributes.user_agent     , UserAgent       ]
])
| table([RequestMethod, RequestPath, APIClientID, IPAddress, UserAgent, LastRequestTime, RequestCount])
| formatTime(format="%F %T", field=LastRequestTime, as=LastRequestTime)
```