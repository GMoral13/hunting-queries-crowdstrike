```
#repo=detections (ExternalApiType=Event_EppDetectionSummaryEvent CustomerIdString=?cid) OR (ExternalApiType=Event_UserActivityAuditEvent Attributes.product= "epp" OperationName=detection_update Attributes.update_status!=new)
| case {
    ExternalApiType=Event_EppDetectionSummaryEvent
        | default(field=[Hostname, UserName], value="--", replaceEmpty=true)
        | DetectDate := rename(UTCTimestamp)
        | Hostname =~ wildcard(?computer, ignoreCase=true)
        | UserName =~ wildcard(?user, ignoreCase=true)
        | in(Name, values=[?scenario], ignoreCase=true)
        | in(SeverityName, values=[?severity]);
    ExternalApiType=Event_UserActivityAuditEvent
        | UpdatedTime := rename(UTCTimestamp);
}
| CompositeId := Attributes.composite_id
| Status := Attributes.update_status
| timelength := length(DetectDate)
| timelengthupdate := length(UpdatedTime)
| case {
  timelength<12
  | DetectDate := (DetectDate*1000);
  *;
}
| case {
  timelengthupdate<12
  | UpdatedTime := (UpdatedTime*1000);
  *;
}
| match("aid_master_main.csv",column=aid, field=AgentIdString, include=[ProductType, event_platform], strict=false)
| case {
    ProductType = 1
        | ProductType := "Workstation";
    ProductType = 2
        | ProductType := "Domain controller";
    ProductType = 3
        | ProductType := "Server";
    event_platform = "Mac"
        | ProductType := "Workstation";
    *;
}
| groupBy([cid, CompositeId], function=[max(UpdatedTime, as=LastUpdate), collect([Name, DetectDate, FalconHostLink, CommandLine, PatternDispositionDescription, Hostname, Attributes.resolution, AgentId]), selectLast([Status, ProcessId, ParentProcessId, ProductType]), collect([MD5String, SHA256String, UserName, SeverityName, Objective, Tactic, Technique, FileName, Description], multival=false)], limit=max)
| SeverityName=*
| default(field=Status, value="new", replaceEmpty=true)
| default(field=Attributes.resolution, value="--", replaceEmpty=true) 
| in(Status, values=[?status])
| Attributes.resolution=?resolution
| Resolution := Attributes.resolution
| join({
    $falcon/investigate:cid_name()
}, field=cid, include=[name], start=1d, mode=left)
| cmd := splitString(CommandLine, by=";")
| CommandLine := concatArray(cmd, separator="\n")
| default(field=[PatternDispositionDescription, Name, ParentProcessId, CommandLine, MD5String, SHA256String, LastUpdate], value="--", replaceEmpty=true)
| DetectDetails := format("Severity: %s\nObjective: %s\nTactic: %s\nTechnique: %s\nDisposition: %s\nScenario: %s\nDescription: %s\nHost Name: %s\nDevice Type: %s\nProcess Id: %s\nFile Name: %s\nCommand Line: %s\nSHA256: %s", field=[SeverityName, Objective, Tactic, Technique, PatternDispositionDescription, Name, Description, Hostname, ProductType, ProcessId, FileName, CommandLine, SHA256String])
| Company := rename(name)
| aid := rename(AgentId)
| DetectDate_UTC_readable := formatTime("%FT%T%z", field=DetectDate)
| LastUpdate_UTC_readable := formatTime("%FT%T%z", field=LastUpdate)
| table([DetectDate, DetectDate_UTC_readable, LastUpdate, LastUpdate_UTC_readable,  Company, SeverityName, Objective, Tactic, Technique, PatternDispositionDescription, Name, Status, Resolution, Hostname, aid, UserName, ProductType, ParentProcessId, ProcessId, FileName, DetectDetails, MD5String, SHA256String, CompositeId, FalconHostLink], sortby=DetectDate, order=desc, limit=20000)
```
