USB Device Insertions with time conversion on the timestamp field and renaming of fields

```
#event_simpleName=DcUsbDeviceConnected
| DeviceTimeStamp:= parseTimeStamp(field=DeviceTimeStamp, format=seconds)
| "Time Inserted" := formatTime("%Y-%m-%dT%H:%M:%S.%L", field=DeviceTimeStamp, timezone="Zulu")
| rename([[ComputerName,"HostName"], [DevicePropertyClassName,"Connection Type"], [DeviceManufacturer,Manufacturer],[DeviceProduct, "Product Name"], [DevicePropertyDeviceDescription, Description], [DevicePropertyClassGuid,GUID], [DeviceInstanceId,"Device ID"]])
| groupBy([aid, "Device ID"], function=([collect(["Time Inserted", ComputerName, "Connection Type", Manufacturer, "Product Name", Description, GUID])]))
```