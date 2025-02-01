from math import sqrt
from secrets import choice
import paho.mqtt.client as mqtt
from time import sleep
import ast
from typing import List, Tuple
import hmac
import hashlib
import json
from Crypto.Cipher import AES
from secrets import token_bytes                                    
                                    

class ComputerB():
    """Represents a device capable of sending and receiving messages using MQTT and encryption."""

    def __init__(
        self,
        broker: str,
        port: int,
        topic: str,
        topic_encryption: str,
        aes_key:int,
        sent_message: str,
        send_mode: bool,
        receive_mode: bool,
    ):
        """
        Initialize the ComputerB object.

        Args:
            broker (str): MQTT broker address.
            port (int): MQTT broker port.
            topic (str): Topic for key exchange.
            topic_encryption (str): Topic for message encryption.
            p (int): Prime modulus.
            private_secret (int): Private key of this device.
            sent_message (str): Message to be sent (in send mode).
            send_mode (bool): Whether the device should encrypt and send a message.
            receive_mode (bool): Whether the device should decrypt a received message.
        """
        # Initialization and MQTT setup
        self.broker = broker
        self.port = port
        self.topic = topic
        self.topic_encryption = topic_encryption
        self.client = mqtt.Client()  # Create an MQTT client instance
        self.client.on_connect = self.on_connect  # Set the callback for connection events
        self.client.on_message = self.on_message  # Set the callback for message receipt
        
        self.aes_key = aes_key
        self.sent_message = sent_message
        self.process_completed = False
        self.send_mode = send_mode
        self.receive_mode = receive_mode

    def encrypt_message(self, msg):
        cipher = AES.new(self.aes_key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(msg.encode('utf-8'))
        return {"nonce": nonce.hex(), "ciphertext": ciphertext.hex(), "tag": tag.hex()}

    def decrypt_message(self, encrypted_payload):
        nonce = bytes.fromhex(encrypted_payload["nonce"])
        ciphertext = bytes.fromhex(encrypted_payload["ciphertext"])
        tag = bytes.fromhex(encrypted_payload["tag"])
        cipher = AES.new(self.aes_key, AES.MODE_EAX, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode('utf-8')
        except ValueError:
            print("Decryption failed. Possible data corruption or tampering.")
            return None

    def on_connect(self, client: mqtt.Client, userdata, flags, rc: int):
        """
        Callback when the MQTT client connects to the broker.

        Args:
            client (mqtt.Client): The client instance.
            userdata: User-defined data.
            flags: Connection flags.
            rc (int): Connection result code.
        """
        print("Connected with result code " + str(rc))  # Print the connection result code
        # Subscribe to the topics for public key exchange and encrypted message reception
        self.client.subscribe(self.topic)
        self.client.subscribe(self.topic_encryption)

    def on_message(self, client: mqtt.Client, userdata, msg: mqtt.MQTTMessage):
        """
        Callback when a message is received on subscribed topics.

        Args:
            client (mqtt.Client): The client instance.
            userdata: User-defined data.
            msg (mqtt.MQTTMessage): The received message.
        """
        # Check if the message is from the expected topic for receiving the public key
        if msg.topic == self.topic:
            try:
                if self.send_mode:
                    # If in send mode, encrypt the message and send it to the encryption topic
                    #AttributeError: 'bytes' object has no attribute 'to_bytes'

                    aes_key_byte = self.aes_key
                    message_byte = self.sent_message.encode('utf-8')
                    tag = hmac.new(aes_key_byte, message_byte, hashlib.sha256).hexdigest()
                    encrypted_message = self.encrypt_message(self.sent_message)
                    print(f"The sent message - {self.sent_message}")
                    payload = {
                        "encrypted_message": json.dumps(encrypted_message),  # Adjust based on the type of encrypted_message
                        "tag": tag
                        }
                    self.client.publish(self.topic_encryption, json.dumps(payload), qos=2)

                    self.process_completed = True  # Mark the process as completed
            except ValueError:
                print("Failed to parse B value.")  # Handle case where B is not a valid integer
        # Check if the message is from the topic where encrypted messages are received
        elif msg.topic == self.topic_encryption and self.receive_mode:
            aes_key_byte = self.aes_key.to_bytes((self.aes_key.bit_length() + 7) // 8, byteorder='big')
            # Deserialize the JSON payload
            try:
                payload = json.loads(msg.payload.decode('utf-8'))  # Decode and parse JSON
                encrypted_message = json.loads(payload["encrypted_message"])
                received_tag = payload["tag"]  # Extract HMAC tag
            except (KeyError, json.JSONDecodeError) as e:
                print(f"Error processing received payload: {e}")
                return
            decrypted_message = self.decrypt_message(encrypted_message)
            message_byte = decrypted_message.encode('utf-8')
            current_tag = hmac.new(aes_key_byte, message_byte, hashlib.sha256).hexdigest()
            if received_tag == current_tag:
                print("HMAC Authentication successful.")
            else:
                print("HMAC Authentication failed")
            print(f"Decrypted message from A: {decrypted_message}")

            self.process_completed = True  # Mark the process as completed

    def run(self):
        """
        Start the MQTT client and send the public key to Computer A.

        This function connects the client to the MQTT broker, starts the client loop, sends
        the public key to Computer A, and then listens for responses until the process is completed.

        Returns:
            None: This function doesn't return any value.
        """
        # Connect to the MQTT broker and start the client loop
        self.client.connect(self.broker, self.port, 60)
        self.client.loop_start()
        try:
            # Generate and send the public key (B) to Computer A
            self.client.publish(self.topic, str(self.aes_key).encode("utf-8"), qos=2)
            # Keep the loop running until stop condition is met
            while True:
                # Break the loop if process is completed.
                if self.process_completed is True: 
                    break
                sleep(0.1)
        finally:
            print("Communication complete. Stopping Computer B.")
            self.client.loop_stop()  # Stop the MQTT client loop
            self.client.disconnect()  # Disconnect from the MQTT broker

aes_key = b'\xa3\xe5\xf0\x1b\x93\x17\x84\x07\xc8\xaf\x88k\xf4\xde\x9c\x12'
broker = "localhost"
port = 1883
topic = "communication/public_key"
topic_encryption = "communication/encryption"

# Instantiate the ComputerB object and run the MQTT client
computer_b = ComputerB(broker, port, topic, topic_encryption, aes_key, "mark13", True, False)
computer_b.run()