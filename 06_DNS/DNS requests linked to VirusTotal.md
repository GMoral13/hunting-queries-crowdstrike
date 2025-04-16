Peticiones DNS con enlace a VT

```
#event_simpleName=/Dns/ ContextBaseFileName=/Code.exe/i
| domain.tld:=splitString(DomainName, by="\.", index=-1) | domain.sld:=splitString(DomainName, by="\.", index=-2)
| case { DomainName=/\..+\./ | registered_domain:=splitString(DomainName, by="\.", index=-3); * }
| case {
    test(length(domain.tld) < 3) | domain.sld=/^([a-z]{2}|com|org|gov|net|biz)$/ domain.sld!=/^(fb|id|hy|ex)$/
      | registered_domain:=format("%s.%s.%s", field=[registered_domain, domain.sld, domain.tld]);
   * | registered_domain:=format("%s.%s", field=[domain.sld, domain.tld])
  }
| day:=time:dayOfYear()
| groupby([registered_domain], function=[count(), unique_subdomains:=count(DomainName, distinct=true), unique_machines:=count(aid, distinct=true), days_seen:=count(day, distinct=true)])
| registered_domain:=format("[%s](https://www.virustotal.com/gui/domain/%s)", field=[registered_domain, registered_domain])
```