Ejecuciones de Powershell encodeadas, mostrando el comando decodeado v2

```
#event_simpleName = ProcessRollup2 AND CommandLine = /powershell/i AND CommandLine = /(encodedcommand|-enc\b|-e\b)/i
| CommandLine = /(encodedcommand|-enc|-e) (?<encoded_string>[^\s]+)/i
| base64Decode(field=encoded_string, as=b64decode, charset="UTF-16LE")
// This case will retrieve nested b64 encodings
| case {b64decode = /powershell/i AND b64decode = /(encodedcommand|-enc\b|-e\b)/i
        | b64decode = /(encodedcommand|-enc|-e) (?<subencoded_string>[^\s]+)/i
        | base64Decode(field=subencoded_string, as=b64decode, charset="UTF-16LE");
        *;
    }
| groupby(b64decode)
```