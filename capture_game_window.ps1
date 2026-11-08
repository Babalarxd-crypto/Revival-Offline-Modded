Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win {
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
  public struct RECT { public int Left, Top, Right, Bottom; }
}
"@
$p = Get-Process BinaryTrU -ErrorAction Stop | Select-Object -First 1
$h = $p.MainWindowHandle
"handle=$h title=$($p.MainWindowTitle)"
if ($h -ne 0) {
  $r = New-Object Win+RECT
  [void][Win]::GetWindowRect($h, [ref]$r)
  $w = $r.Right - $r.Left; $ht = $r.Bottom - $r.Top
  "rect=$($r.Left),$($r.Top) ${w}x${ht}"
  if ($w -gt 0 -and $ht -gt 0) {
    $bmp = New-Object System.Drawing.Bitmap $w, $ht
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($r.Left, $r.Top, 0, 0, $bmp.Size)
    $bmp.Save('C:\Users\Biqivet\AppData\Local\Temp\opencode\cap\game-screen.png')
    $g.Dispose(); $bmp.Dispose()
    "saved"
  }
}
