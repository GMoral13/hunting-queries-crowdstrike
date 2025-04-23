Contained hosts

```
"#event_simpleName" = SensorHeartbeat OR "#event_simpleName" = AgentConnect
| NetworkContainmentState = "1"
| rename(field="aip", as="IPProxy")
| groupBy([aid], limit=max, function=selectLast([@timestamp, ComputerName, IPProxy, LocalIP, event_platform]))
| sort(@timestamp, order=desc)
```