/bin/bash -ex

sudo iw phy phy0 interface add mon0 type monitor
sudo iw dev wlan0 del
sudo ifconfig mon0 up
sudo iw dev mon0 set channel 11
iwconfig mon0


# sudo python send.py "here is some dat" && sleep 1 && sudo python send.py "here is some dat" && sleep 1 && sudo python send.py "here is some dat" && sleep 1 && sudo python send.py "here is some dat"
