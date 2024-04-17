Summary: CD Log Agent
Name: cdlog
Version: 2.0
Release: 1
License: MIT
Group: Applications/System
Source0: cdlog
Source1: cdlog.conf
Source2: cdlog.service

%description
CD Log Agent

%install
# Create directories
mkdir -p %{buildroot}/etc/cdlog
mkdir -p %{buildroot}/etc/systemd/system

# Copy files
cp %{SOURCE0} %{buildroot}/etc/cdlog/cdlog
cp %{SOURCE1} %{buildroot}/etc/cdlog/cdlog.conf
cp %{SOURCE2} %{buildroot}/etc/systemd/system/cdlog.service
mkdir /etc/cdlog
cp %{SOURCE0} /etc/cdlog/cdlog
cp %{SOURCE1} /etc/cdlog/cdlog.conf
cp %{SOURCE2} /etc/systemd/system/cdlog.service
# Reload systemd to pick up new service unit file
sudo systemctl daemon-reload

# Enable and start the service
sudo systemctl enable cdlog.service
sudo systemctl start cdlog.service

%pre
# creating user cdlog and giving minimum premissions
sudo useradd cdlog
chmod +x /etc/cdlog/cdlog
mkdir /etc/cdlog

%files
%defattr(-,root,root)
/etc/cdlog/cdlog
/etc/cdlog/cdlog.conf
/etc/systemd/system/cdlog.service

%changelog
* Fri Apr 16 2024 John Doe <john@example.com> 1.0-1
- Initial build

