# Unassociated Transfer

This library allows an Ethernet connected device to send data to an unassociated wireless device. It is assumed that there is an interface that is in monitor mode on a WiFi channel that the access point is transmitting on.


## Dependencies

```
sudo apt install -y python-pip python-dev libxml2-dev libxslt1-dev tcpdump tshark python-lxml
sudo pip install -r requirements.txt
```


## Example

On the unassociated device in monitor mode:

```
sudo python receive.py mon0
```

`mon0` is the interface for the device in monitor mode.

On the Ethernet connected device:

```
sudo python send.py "here is some dat"
```

The data that is sent must be divisible by 16. This is a requirement of the encryption algorithm. Padding can be added to solve this problem. This only supports Python 2.7.

