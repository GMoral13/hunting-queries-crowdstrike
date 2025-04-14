#repo=detections (ExternalApiType=Event_EppDetectionSummaryEvent CustomerIdString=?cid) OR (ExternalApiType=Event_UserActivityAuditEvent Attributes.product="epp" OperationName=detection_update)
| CompositeId := Attributes.composite_id
| case{
ExternalApiType=Event_UserActivityAuditEvent Attributes.update_status=closed | response_time:=@timestamp;
ExternalApiType=Event_EppDetectionSummaryEvent | detect_time:=@timestamp;
*;
}
/* Do not merge this case with the case statement above. Sometimes a detection is assigned and closed in
   the same audit event. Having two different case statements ensures we get both timestamps. */ 
| case{
ExternalApiType=Event_UserActivityAuditEvent Attributes.assign_to_uuid=* | assign_time:=@timestamp;
*;
}
| groupBy([CompositeId], function=([count(ExternalApiType, distinct=true), selectLast([Hostname, Attributes.update_status, SeverityName]), collect([Tactic, Technique, FalconHostLink, Attributes.resolution]), min(detect_time, as=FirstDetect), min(assign_time, as=FirstAssign), min(response_time, as=ResolvedTime)]), limit=max)
| Hostname=?computer
| in(Tactic, values=[?tactic], ignoreCase=true)
| in(SeverityName, values=[?severity])
// This handles when an alert was closed and then reopened
| case {
Attributes.update_status!=closed | ResolvedTime:="";
*;
}
| ToAssign:=(FirstAssign-FirstDetect) | ToAssign:=formatDuration(field=ToAssign, precision=3)
| AssignToClose:=(ResolvedTime-FirstAssign) | AssignToClose:=formatDuration(field=AssignToClose, precision=3)
| DetectToClose:=(ResolvedTime-FirstDetect) | DetectToClose:=formatDuration(field=DetectToClose, precision=3)

// Calculate the age of open alerts
| case{
    Attributes.update_status!="closed" | Aging:=now()-FirstDetect | Aging:=formatDuration(Aging, precision=2);
    *;
}
| default(field=Attributes.resolution, value="--", replaceEmpty=true) 
| Attributes.resolution=?resolution
| Resolution := rename(Attributes.resolution)
| default(value="new", field=[Attributes.update_status])
| Attributes.update_status = ?status
| default(value="--", field=[Hostname, FirstAssign, ResolvedTime, ToAssign, AssignToClose, DetectToClose, Aging, Resolution], replaceEmpty=true)
| FirstDetect_readable := formatTime(format="%FT%T%z", field="FirstDetect")
| FirstAssign_readable := formatTime(format="%FT%T%z", field="FirstAssign")
| ResolvedTime_readable := formatTime(format="%FT%T%z", field="ResolvedTime")
| format("[Detection Link](%s)", field=[FalconHostLink], as="Detection Link")
| "Status" :=rename(Attributes.update_status)
| table([Hostname, Tactic, Technique, SeverityName, Status, Aging, FirstDetect, FirstDetect_readable, FirstAssign, FirstAssign_readable, ResolvedTime, ResolvedTime_readable, ToAssign, AssignToClose, DetectToClose, Resolution, "Detection Link", CompositeId], sortby=Aging, order=desc, limit=20000)
