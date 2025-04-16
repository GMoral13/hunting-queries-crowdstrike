Show volume mounts for removable media

```
#event_simpleName=RemovableMediaVolumeMounted
| table([ComputerName, VolumeDriveLetter, VolumeFileSystemDevice, VolumeFileSystemDriver])
```