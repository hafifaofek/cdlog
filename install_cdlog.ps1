# Define variables
$serviceName = "cdlogService3"
$servicePath = "C:\Program Files\cdlog\cdlog.exe"
$serviceConfigPath = "C:\Program Files\cdlog\cdlog.conf"

# Copy files to installation directory
$installDir = "C:\Program Files\cdlog"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item ".\cdlog.exe" -Destination "$installDir\cdlog.exe" -Force
Copy-Item ".\cdlog.conf" -Destination "$installDir\cdlog.conf" -Force

#attrib -r "C:\Program Files\cdlog"

# Grant execute permissions to the directory and its contents
#icacls $installDir /grant Users:RX /T
#icacls $servicePath /grant Users:RX /T

## Install the service
./nssm.exe install $serviceName $servicePath
net start $serviceName

Write-Host "cdlog service installed and started successfully."