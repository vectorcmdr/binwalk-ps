# binwalk-ps

PowerShell binwalk port for personal use. <br/>

### Purpose:
Same old features, just in a `.ps1`. Scans a binary blob for magic bytes of known file formats and reports offsets, types, and estimated sizes. Optionally carve and dump each hit.

### Usage:

#### Example:
```
.\binwalk.ps1 firmware.bin
.\binwalk.ps1 firmware.bin -Dump -OutDir C:\stuff\carved
```

#### Params:
`Path` - Path to the binary file to scan.
`Dump` - If set, carve each identified signature into a separate file under -OutDir.
`OutDir` - Output directory for carved files (default: <filename>_carved).
`Offset` - Start scanning at this byte offset (default 0).
`Length` - Number of bytes to scan from the start offset (default: rest of file).
`Quiet` - Suppress verbose progress.

### License
#### MIT License - go nuts.
