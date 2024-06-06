ipset -N tor iphash
# get a list of Tor exit nodes skipping comments
wget -q https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=$YOUR_IP -O -| sed '/^#/d' | while read IP
do
  # add each IP address to the new set, silencing the warnings for IPs that have already been added
  ipset -q -A tor $IP
done
# filter our new set in iptables
iptables -A INPUT -m set --match-set tor src -j DROP