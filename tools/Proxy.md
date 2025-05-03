# HomeConnect Websocket MITM Proxy

Simple Man-in-the-middle proxy to watch HomeConnect Websocket traffic.
This is accomplished by using an iptables rule on the phone to redirect the Websocket connection to a Computer running the proxy script.
The proxy the connects to the Appliance and forwards all messages.

## Requirements

* Rooted Android phone with installed HomeConnect App
* The Appliance encryption Keys
* Python >=3.13 and homeconnect_websocket installed

## Setup NAT on An

1. Connect with adb
2. Disable IPv6

    ```bash
    echo 1 | tee /proc/sys/net/ipv6/conf/all/disable_ipv6
    echo 0 | tee /proc/sys/net/ipv6/conf/wlan0/accept_ra
    ```

3. Setup NAT

    ```bash
    iptables -t nat -A OUTPUT -d [Appliance IP] -p tcp --dport 443 -j DNAT --to-destination [Proxy IP]:443
    ```

for AES replace port 443 with port 80

## Run Proxy

```bash
python hc_proxy.py [Appliance IP] -psk [Appliance PSK] -o proxy.log (-iv [Appliance IV])
```
