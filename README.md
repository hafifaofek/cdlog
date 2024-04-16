# cdlog
CDLOG agent collects data from predefinds files in the computer.
conf file is at - /etc/cdlog/cdlog.conf

The directory cdlog_package contains all of files needed for the cdlog agent to work.
All you need to do is to run the install.sh file and everything will be set, you can copy this command - 
sudo ./install.sh

And that's it, you are all set :)

You may use the next command in order to see the running service-
journalctl -f -u cdlog.service
f