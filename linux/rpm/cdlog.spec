# Define some basic information about the package
Name:           cdlog
Version:        1.0
Release:        1%{?dist}
Summary:        CD Log Agent

# Define the license
License:        MIT

# Define the source file (your compiled Python agent)
Source:         cdlog

# Define the dependencies (if any)
Requires:       python3, systemd

%description
Your Python agent description.

# Define the pre-install scriptlet
%pre
# Create the necessary directory structure
mkdir -p %{buildroot}/etc/cdlog
# Copy the configuration file
cp cdlog.conf %{buildroot}/etc/cdlog/cdlog.conf

# Define the files to be installed
%files
%{buildroot}/cdlog
%{buildroot}/etc/cdlog/cdlog.conf
%{_unitdir}/cdlog.service

# Define the scriptlets for systemd services
%post
/bin/systemctl daemon-reload

# Define the installation location of the service file
%{_unitdir}/cdlog.service

# End of spec file
