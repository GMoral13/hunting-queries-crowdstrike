Búsqueda de VPNs

```
#event_simpleName=ProcessRollup2 AND ((FileName=openvpn.exe OR CommandLine=*openvpn*) OR
(FileName=openvpn.exe OR CommandLine=*openvpn*) OR
(FileName=vpnd.exe OR CommandLine=*vpnd*) OR
(FileName=openvpn.exe OR CommandLine=*openvpn*) OR
(FileName=protonvpn.exe OR CommandLine=*protonvpn*) OR
(FileName=nordvpn.exe OR CommandLine=*nordvpn*) OR
(FileName=windscribe.exe OR CommandLine=*windscribe*) OR
(FileName=surfshark.exe OR CommandLine=*surfshark*) OR
(FileName=cyberghost.exe OR CommandLine=*cyberghost*) OR
(FileName=hotspotshield.exe OR CommandLine=*hotspotshield*) OR
(FileName=hsswd.exe OR CommandLine=*hsswd*) OR
(FileName=torguard.exe OR CommandLine=*torguard*) OR
(FileName=pia_manager.exe OR CommandLine=*pia_manager*))
| groupBy([FileName, ComputerName])
```