Query to detect function GetClipboardData() in Crowdstrike (T1115)

Detect/search for any events where an adversary/infosec stealer/suspicious software is using the Get-Clipboard cmdlet to access the Clipboard Data.

```
#event_simpleName=/(Script|ProcessRollup2|CommandHistory)/
| case {
    #event_simpleName=/Script/iF     | Where:="Script Content"         | ScriptContent=/Get-Clipboard/iF;
    #event_simpleName=ProcessRollup2 | Where:="Command Line"            | CommandLine=/Get-Clipboard/iF;
    #event_simpleName=CommandHistory | Where:="Command Line History"    | CommandHistory=/Get-Clipboard/iF;
}
| Data:=coalesce([CommandLine, CommandHistory, ScriptContent])
| table([@timestamp, aid, ComputerName, Where, Data])
```