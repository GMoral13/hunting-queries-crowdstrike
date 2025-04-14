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
| match("aid_master_main.csv",column=aid, field=AgentIdString, include=[ProductType, event_platform], strict=false)
| groupBy([cid, CompositeId], function=[max(UpdatedTime, as=LastUpdate), collect([Name, DetectDate, CommandLine, PatternDispositionDescription, Hostname, Attributes.assign_to_name, AgentId]), selectLast([Status]), collect([UserName, SeverityName, Objective, Tactic, Technique, Description], multival=false)], limit=max)
| default(field=Attributes.assign_to_name, value="--", replaceEmpty=true) 
| default(field=Status, value="new", replaceEmpty=true)
| in(Status, values=[?status])
| Attributes.assign_to_name=?assign_to_name
| Asignado := Attributes.assign_to_name
| join({
    $falcon/investigate:cid_name()
}, field=cid, include=[name], start=1d, mode=left)
| cmd := splitString(CommandLine, by=";")
| CommandLine := concatArray(cmd, separator="\n")
| default(field=[PatternDispositionDescription, Name, CommandLine, LastUpdate], value="--", replaceEmpty=true)
| table([DetectDate, Hostname, UserName, SeverityName, Status, Asignado, PatternDispositionDescription, Name], sortby=DetectDate, order=desc, limit=20000)
| Status != closed
```
