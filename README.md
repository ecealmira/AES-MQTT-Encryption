# AES-MQTT-Encryption
This project implements secure communication between two devices using MQTT and AES encryption. The communication is established between Computer A and Computer B, where messages are encrypted using AES before transmission and decrypted upon reception. An additional layer of security is provided through HMAC authentication.

## Features

- MQTT-based communication between two devices.

- AES Encryption (EAX Mode) for secure message transmission.

- HMAC Authentication for message integrity verification.

- Bidirectional communication between devices.

- Python implementation with the paho-mqtt library.

## Setup & Usage

1. Configure the MQTT Broker

Ensure you have an MQTT broker running (such as Mosquitto). You can install it using:
```
sudo apt install mosquitto mosquitto-clients
```
Start the MQTT broker:
```
mosquitto -v
```
2. Run Computer A
```
python computer_a.py
```
3. Run Computer B
```
python computer_b.py
```
