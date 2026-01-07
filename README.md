# Filedropper

Simple and secure file hosting web service in Go.

Install with:
```bash
go install github.com/fullfox/filedropper@latest
```

## Upload via commands

**curl:**
```bash
curl -T myfile.txt "https://filedropper.eu/upload/myfile.txt"
```
```bash
curl -T myfile.txt "https://filedropper.eu/upload/myfile.txt?expiration=168h&public=yes"
```

**PowerShell:**
```powershell
iwr -Uri "https://filedropper.eu/upload/myfile.txt" -UseBasicParsing -Method Put -InFile myfile.txt
```
```powershell
iwr -Uri "https://filedropper.eu/upload/myfile.txt?expiration=168h&public=yes" -UseBasicParsing -Method Put -InFile myfile.txt
```

**URL Parameters:**
- `expiration` - Duration in hours (e.g., `1h`, `24h`, `168h`). Default: `168h` (7 days)
- `public` - Set to `yes` to list file publicly. Default: not public
