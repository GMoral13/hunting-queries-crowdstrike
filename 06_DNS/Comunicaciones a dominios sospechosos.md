Comunicaciones a dominios sospechosos:

```
in("DomainName", values=["sync.com","egnyte.com","terabox.com","onehub.com","storyblok.com","vatacloud.com","freeupload.store","hopto.org"])
| table([cid, aid, #event_simpleName, ComputerName, DomainName])
```