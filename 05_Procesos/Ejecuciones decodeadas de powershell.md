Ejecuciones de Powershell encodeadas, mostrando el comando decodeado

```
//Grab all PowerShell execution events
#event_simpleName=ProcessRollup2 event_platform=Win ImageFileName=/\\powershell(_ise)?\.exe/i
//Look for command line flags that indicate an encoded command
| CommandLine=/\s+\-(e\s|enc|encodedcommand|encode)\s+/i
//Group by command frequency
| groupby([ParentBaseFileName, CommandLine], function=stats([count(aid, distinct=true, as="uniqueEndpointCount"), count(aid, as="executionCount")]), limit=max)
//Setting prevalence threshold
| uniqueEndpointCount < 3
//Calculating the length of the encrypted command line
| cmdLength := length("CommandLine")
//Isolate Base64 String
| CommandLine=/\s+\-(e\s|enc|encodedcommand|encode)\s+(?<base64String>\S+)/i
//Get Entropy of Base64 String
| b64Entroy := shannonEntropy("base64String")
//Decode encoded command blob
| decodedCommand := base64Decode(base64String, charset="UTF-16LE")
| table([ParentBaseFileName, uniqueEndpointCount, executionCount, cmdLength,  b64Entroy, decodedCommand])
```