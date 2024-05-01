#sc.exe delete cdlog

# Define variables
$serviceName = "cdlog"
$servicePath = "C:\Program Files\cdlog\cdlog.exe"
$serviceConfigPath = "C:\Program Files\cdlog\cdlog.conf"

# Copy files to installation directory
$installDir = "C:\Program Files\cdlog"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item ".\cdlog.exe" -Destination "$installDir\cdlog.exe" -Force
Copy-Item ".\cdlog.conf" -Destination "$installDir\cdlog.conf" -Force

# Install the service
sc.exe create $serviceName binPath= $servicePath start= auto
sc.exe start $serviceName

Write-Host "cdlog service installed and started successfully."
