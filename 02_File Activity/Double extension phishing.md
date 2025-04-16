Queries to threat hunt double extension attacks with Crowdstrike Logscale.
Common Scenario: Phishing email contains link to download business "pdf" > "pdf" downloaded > pdf double clicked > zip extracted > payload runs

```
//This is the base search. It looks for file names that end with html or txt or pdf or doc or ppt but have a .zip extension. 
#repo=base_sensor  #event_simpleName=ZipFileWritten //look for Zips only
FileName=/(txt|pdf|doc|docm|ppt|html)\.zip/i    //look for Zips with interesting names (add file types as needed ;))
| groupBy([#event_simpleName,FileName],function =(count(FileName, as=FileNameCount))) //count filenames and group by filenames to determine prevalence and context
```

```
//Pivot off suspicious filename and search the extracted file name for interesting events that may indicate threat actor activity
ComputerName="my_host" //for efficiency specify host + time range
( FileName=*sus_pdf* or CommandLine=*sus_pdf*) //need wild card for filen ame as it could have any file extension + command line is needed as that is where the pdf name will be in the CS log when opened with pdf viewer or other program
(#event_simpleName=ProcessRollup2 or #event_simpleName=*Written* or #event_simpleName=*File* or #event_simpleName=*Script* or #event_simpleName=MotwWritten or #event_simpleName=DirectoryCreate) //logs of interest based on testing
(ContextBaseFileName=outlook.exe or //catch all to determine if file from email
ContextBaseFileName=explorer.exe or //catch all to determine what occurred after file was saved to disk
TargetFileName=/\\Device\\HarddiskVolume\d\\Users\\.+\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\.*$/ or  //do not escape .+ - CS TAM looking into this quirk
TargetFileName=/\\Device\\HarddiskVolume\d\\Users\\.+\\Downloads\\/ or //search some directories of interest
TargetFileName=/^\\Device\\HarddiskVolume\d\\Temp\\.+/ or
ImageFileName=/^\\Device\\HarddiskVolume\d\\Program Files \(x86\)\\Adobe\\Acrobat Reader.+\\Reader\\AcroRd32\.exe$/ or //any version of Acrobat Reader but may need to expand //to ImageFileName=*Adobe*
ImageFileName=/^\\Device\\HarddiskVolume\d\\Windows\\System32\\WindowsPowerShell\\v\d\.0\\powershell\.exe$/ or  //any version of PS but may need to expand //to ImageFileName=*powershell*
ImageFileName=/^\\Device\\HarddiskVolume\d\\Windows\\System32\\\w+\.exe$/)  //any version of notepad but may need to expand //to ImageFileName=*texteditorhere*
|$falcon/helper:enrich(field="FileCategory") //convert decimal to ascii for readability
| select([@timestamp,#event_simpleName,name, Tactic, UserName, ComputerName,ContextBaseFileName, FileName, FileCategory, FilePath, TargetFileName, CommandLine])
| sort(@timestamp, order=asc) //sort for chronological time
```

```
//Pivot to look at all 1000+ crowdstrike event types (cs data dictionary is a great resource to understand the event types)
ComputerName="my_host" //for efficiency specify host + time range
( FileName=*sus_pdf* or CommandLine=*sus_pdf*) //need wild card for file name as it could have any file extension + command line is needed as that is where the pdf name will be in the CS log when opened with pdf viewer or other program
| select([@timestamp,#event_simpleName,FileName, ContextBaseFileName, TargetFileName,  CommandLine,name, Tactic, UserName, ComputerName,  FilePath, CommandLine])
| sort(@timestamp, order=asc) //sort for chronological time
```