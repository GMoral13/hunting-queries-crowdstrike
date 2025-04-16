Consultas DNS desde navegadores a un un dominio

```
#event_simpleName=DnsRequest
| DomainName="*domain.com"
| ContextBaseFileName =~ !in(values=["firefox.exe", "chrome.exe", "msedge.exe"])
| groupBy([DomainName, ComputerName])
```