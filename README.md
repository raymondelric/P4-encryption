# P4-encryption
CS 6114 final project

## Threat Model and Motivation
A lot of IoT devices are transferring the data to server in plaintext because of their limitation in computing. It is extremely easy to sniff these data. For example, if we are sniffing on the tunnel between a server and the wearable devices, we can keep track of the any data collected by the device, leading to privacy leakage. Considering a more serious senario, if a central controller could decide when to open the window depending on the temperature, the thief can maliciously fake the current temperature in order to open the window and get into the house.

## Proposal

![alt text](https://github.com/raymondelric/P4-encryption/blob/master/img/proposal.jpg)

Before sending out the packets to the server, the switch in our house will check whether the packet is encrypted. In this case, even there is an attacker sniffing, all he can retrieve is the ciphertext.

Also, we make two assumption about this scenario:
First, we trust the router that is in our house; second, the server is powerful enough that it does not have to rely on switch decryption.

## Implementations

- [x] Modified the packet structure to fit our requirements: added a header structure, payload, to store the message and other information we need
- [x] Bind Payload structure with TCP
- [x] Modified send.py to store the message as int
- [x] Implemented XOR in switch to encrypt
- [x] Implemented Caesar in switch to encrypt
- [x] Implemented Feistel in switch to encrypt
- [x] Implemented switch so that the message is only encrypted at first time
- [x] Implemented choices of different cipher methods
- [x] Implemented choices of different keys
- [x] Made sure our basic switch can forward and encrypt the packet correctly
- [x] Verified correctness of encryption in receive.py
- [ ] Expand packet size so that packet could handle large data
- [ ] Accept string as input type
- [ ] Implement loop in P4 in order to use more encryption methods
