<#
.SYNOPSIS
  binwalk for Windows - scans binary files for embedded file signatures.
.DESCRIPTION
  Scans a binary blob for magic bytes of known file formats and reports
  offsets, types, and estimated sizes. Optionally carve and dump each hit.
.PARAMETER Path
  Path to the binary file to scan.
.PARAMETER Dump
  If set, carve each identified signature into a separate file under -OutDir.
.PARAMETER OutDir
  Output directory for carved files (default: <filename>_carved).
.PARAMETER Offset
  Start scanning at this byte offset (default 0).
.PARAMETER Length
  Number of bytes to scan from the start offset (default: rest of file).
.PARAMETER Quiet
  Suppress verbose progress.
.EXAMPLE
  .\binwalk.ps1 firmware.bin
  .\binwalk.ps1 firmware.bin -Dump -OutDir C:\tmp\carved
#>

param(
  [Parameter(Mandatory, Position = 0)]
  [string]$Path,
  [switch]$Dump,
  [string]$OutDir = "",
  [long]$Offset = 0,
  [long]$Length = 0,
  [switch]$Quiet
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Signature database
# ---------------------------------------------------------------------------
$Signatures = @(
  # Images
  @{ Magic = [byte[]]@(0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A); Label="PNG image" }
  @{ Magic = [byte[]]@(0xFF,0xD8,0xFF);                          Label="JPEG image" }
  @{ Magic = [byte[]]@(0x47,0x49,0x46,0x38);                     Label="GIF image" }
  @{ Magic = [byte[]]@(0x42,0x4D);                               Label="BMP image" }
  @{ Magic = [byte[]]@(0x52,0x49,0x46,0x46);                     Label="WebP / RIFF" }

  # Archives
  @{ Magic = [byte[]]@(0x50,0x4B,0x03,0x04);                     Label="ZIP archive" }
  @{ Magic = [byte[]]@(0x50,0x4B,0x05,0x06);                     Label="ZIP archive (EOCD)" }
  @{ Magic = [byte[]]@(0x50,0x4B,0x07,0x08);                     Label="ZIP archive (spanned)" }
  @{ Magic = [byte[]]@(0x1F,0x8B);                               Label="GZIP compressed" }
  @{ Magic = [byte[]]@(0x42,0x5A,0x68);                          Label="BZIP2 compressed" }
  @{ Magic = [byte[]]@(0xFD,0x37,0x7A,0x58,0x5A,0x00);           Label="XZ compressed" }
  @{ Magic = [byte[]]@(0x52,0x61,0x72,0x21,0x1A,0x07);           Label="RAR archive" }
  @{ Magic = [byte[]]@(0x52,0x61,0x72,0x21,0x1A,0x07,0x00);      Label="RAR archive (v5)" }
  @{ Magic = [byte[]]@(0x37,0x7A,0xBC,0xAF,0x27,0x1C);           Label="7z archive" }

  # Executables
  @{ Magic = [byte[]]@(0x4D,0x5A);                               Label="MZ executable (DOS/PE)" }
  @{ Magic = [byte[]]@(0x7F,0x45,0x4C,0x46);                     Label="ELF" }
  @{ Magic = [byte[]]@(0xCA,0xFE,0xBA,0xBE);                     Label="Mach-O (fat)" }
  @{ Magic = [byte[]]@(0xCF,0xFA,0xED,0xFE);                     Label="Mach-O (64-bit)" }

  # Firmware / boot
  @{ Magic = [byte[]]@(0xEA,0x00,0x00,0x00);                     Label="U-Boot image header" }
  @{ Magic = [byte[]]@(0x27,0x05,0x19,0x56);                     Label="U-Boot legacy image" }
  @{ Magic = [byte[]]@(0x41,0x52,0x4D,0x59);                     Label="ARM TF (FIP)" }

  # Filesystems
  @{ Magic = [byte[]]@(0x68,0x73,0x71,0x73);                     Label="SquashFS (LE)" }
  @{ Magic = [byte[]]@(0x73,0x71,0x73,0x68);                     Label="SquashFS (BE)" }
  @{ Magic = [byte[]]@(0xD7,0xB7,0xAB,0x1E);                     Label="UBIFS" }
  @{ Magic = [byte[]]@(0x19,0x85,0x20,0x03);                     Label="CramFS" }

  # Crypto / web / misc
  @{ Magic = [byte[]]@(0x30,0x82);                               Label="DER X.509 cert" }
  @{ Magic = [byte[]]@(0x25,0x50,0x44,0x46);                     Label="PDF document" }
  @{ Magic = [byte[]]@(0x3C,0x3F,0x78,0x6D,0x6C);                Label="XML declaration" }
  @{ Magic = [byte[]]@(0x3C,0x68,0x74,0x6D,0x6C);                Label="HTML" }
  @{ Magic = [byte[]]@(0x41,0x4E,0x44,0x52,0x4F,0x49,0x44);      Label="Android boot img" }
)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
  Write-Error "File not found: $Path"
  exit 1
}

$fi = Get-Item -LiteralPath $Path
$fileLen = $fi.Length
if ($Length -le 0) { $Length = $fileLen - $Offset }

if (-not $Quiet) {
  Write-Host "Binwalk scanning '$($fi.Name)' ($fileLen bytes)" -ForegroundColor Cyan
}

# Load file into memory
$scanLen = [Math]::Min($Length, $fileLen - $Offset)
if (-not $Quiet -and $scanLen -gt 200MB) {
  Write-Host "  Warning: $scanLen bytes may use significant memory." -ForegroundColor Yellow
}
$data = [System.IO.File]::ReadAllBytes($fi.FullName)
if ($Offset -gt 0 -or $scanLen -lt $data.Count) {
  $data = $data[$Offset..($Offset + $scanLen - 1)]
}
$dataLen = $data.Count

$hits = @()
for ($pos = 0; $pos -lt $dataLen; $pos++) {
  $remaining = $dataLen - $pos
  foreach ($sig in $Signatures) {
    $magic = $sig.Magic
    if ($remaining -lt $magic.Count) { continue }
    $match = $true
    for ($j = 0; $j -lt $magic.Count; $j++) {
      if ($data[$pos + $j] -ne $magic[$j]) { $match = $false; break }
    }
    if (-not $match) { continue }

    # Try to determine size for formats that encode it
    $size = 0
    $sizeOff = $pos + $magic.Count

    # PNG: big-endian 4-byte chunk length at offset 16 (after magic + IHDR header)
    if ($sig.Label -eq "PNG image" -and ($pos + 16 + 4) -le $dataLen) {
      $size = [int](($data[$pos+16] -shl 24) -bor ($data[$pos+17] -shl 16) -bor ($data[$pos+18] -shl 8) -bor $data[$pos+19]) + 33
    }
    # BMP: little-endian file size at offset 2
    if ($sig.Label -eq "BMP image" -and ($pos + 2 + 4) -le $dataLen) {
      $size = [int](($data[$pos+2] -shl 0) -bor ($data[$pos+3] -shl 8) -bor ($data[$pos+4] -shl 16) -bor ($data[$pos+5] -shl 24))
    }

    $absPos = $Offset + $pos
    $hits += [PSCustomObject]@{ Offset = $absPos; Size = $size; Label = $sig.Label }

    if (-not $Quiet) {
      Write-Host "  [0x$(('{0:X8}' -f $absPos))] $($sig.Label)" -ForegroundColor Green
    }
    break
  }

  if (-not $Quiet -and ($pos % 10MB) -eq 0 -and $pos -gt 0) {
    $pct = [Math]::Min(100, [int]($pos * 100 / $dataLen))
    Write-Host "  ... $pct% ($($Offset+$pos) / $($Offset+$dataLen))" -ForegroundColor DarkGray
  }
}

$data = $null

if ($hits.Count -eq 0) {
  Write-Host "No signatures found." -ForegroundColor Yellow
  exit 0
}

Write-Host "`nFound $($hits.Count) signature(s):" -ForegroundColor Cyan
$hits | Format-Table -AutoSize -Property @{N="Offset";E={"0x$(('{0:X8}' -f $_.Offset))"}},
  @{N="Size";E={ if ($_.Size -gt 0) { $_.Size.ToString("N0") } else { "?" } }},
  Label

# Dump / carve
if ($Dump) {
  if (-not $OutDir) { $OutDir = "$($fi.DirectoryName)\$($fi.BaseName)_carved" }
  $null = New-Item -ItemType Directory -Path $OutDir -Force -ErrorAction SilentlyContinue

  $reader = $null
  try {
    $reader = [System.IO.File]::OpenRead($fi.FullName)
    foreach ($hit in $hits) {
      $reader.Position = $hit.Offset
      $size = $hit.Size
      if ($size -le 0) {
        $size = [Math]::Min(256KB, $fileLen - $hit.Offset)
      }
      if ($size -le 0) { continue }

      $buf = New-Object byte[] $size
      $read = $reader.Read($buf, 0, $size)
      $safeName = ($hit.Label -replace '[^a-zA-Z0-9_-]', '_')
      $outPath = Join-Path $OutDir "0x$(('{0:X8}' -f $hit.Offset))_$safeName.bin"
      [System.IO.File]::WriteAllBytes($outPath, $buf[0..($read-1)])
      Write-Host "  Carved -> $outPath ($read bytes)" -ForegroundColor Magenta
    }
  } finally {
    if ($reader) { $reader.Close() }
  }
}
