# P4-encryption
CS 6114 final project

## Threat Model and Motivation
A lot of IoT devices are transferring the data to server in plaintext because of their limitation in computing. It is extremely easy to sniff these data. For example, if we are sniffing on the tunnel between a server and the wearable devices, we can keep track of the any data collected by the device, leading to privacy leakage. Considering a more serious senario, if a central controller could decide when to open the window depending on the temperature, the thief can maliciously fake the current temperature in order to open the window and get into the house.

## Proposal

Before sending out the packets to the server, the switch in our house will check whether the packet is encrypted. In this case, even there is an attacker sniffing, all he can retrieve is the ciphertext.

Also, we make two assumption about this scenario:
First, we trust the router that is in our house; second, the server is powerful enough that it does not have to rely on switch decryption.
