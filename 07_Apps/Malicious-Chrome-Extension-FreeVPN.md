This Logic detects the presence of the malicious Chrome extension FreeVPN[.]One by identifying its unique extension ID across installed browsers. The logic further correlates this presence with network communications initiated by the extension to suspicious or untrusted domains. By combining extension enumeration with traffic analysis, the detection ensures high fidelity with minimal false positives. This layered approach strengthens visibility into malicious browser add-ons masquerading as VPN tools.

```
defineTable(query={#event_simpleName=InstalledBrowserExtension
|case{
    BrowserExtensionId=/jcbiifklmgnkppebelchllpdbnibihel/iF;
    BrowserExtensionName=/FreeVPN/iF
}
| case{ 
    "BrowserExtensionStatusEnabled"="0" | BrowserExtensionStatusEnabled:="Disabled";
    "BrowserExtensionStatusEnabled"="1" | BrowserExtensionStatusEnabled:="Enabled";
    *;
}
| BrowserExtensionInstalledTimestamp := BrowserExtensionInstalledTimestamp * 1000
| "Extension Installation date" := formatTime("%d-%m-%Y %H:%M:%S.%L", field=BrowserExtensionInstalledTimestamp, locale=en_UAE, timezone="Asia/Dubai")
| "Extension(s)":=format(format="Status=%s, Installation Date=%s", field=[BrowserExtensionStatusEnabled,"Extension Installation date"])
| groupBy([event_platform, aid, UserName, BrowserProfileId, BrowserName,BrowserExtensionName], function=([collect([ComputerName,"Extension(s)",BrowserExtensionPath,BrowserExtensionRequestedPermissions])]))
| drop([_count,aid])
| case{ 
    BrowserName ="0" | BrowserName := "UNKNOWN" ;
    BrowserName="1" | BrowserName:="Firefox";
    BrowserName="2" | BrowserName:="Safari";
    BrowserName="3" | BrowserName:="Chrome";
    BrowserName="4" | BrowserName:="Edge";
    BrowserName="5" | BrowserName:="EDGE CHROMIUM";
    BrowserName="6" | BrowserName:="Internet Explorer";
    BrowserName="7" | BrowserName:="Edge Legacy";
    BrowserName="8" | BrowserName:="IE_TYPED_URL";
    BrowserName="9" | BrowserName:="FIREFOX_APP";
    *;
}}, include=[*], name="Extension")
|defineTable(query={#event_simpleName=DnsRequest | in(field="DomainName", values=["aitd.one","extrahefty.com","scan.aitd.one","freevpn.one"],ignoreCase=true)}, include=[*], name="ExtensionTraffic")
|readFile(["Extension","ExtensionTraffic"])
|groupBy([ComputerName,DomainName], function=([collect([UserName, BrowserProfileId, BrowserName,BrowserExtensionName,"Extension(s)",BrowserExtensionPath,BrowserExtensionRequestedPermissions])]))
```