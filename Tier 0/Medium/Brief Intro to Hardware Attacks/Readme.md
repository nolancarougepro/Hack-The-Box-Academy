## Introduction : 

Bluetooth technology, designed for short-range wireless communication between devices. Despite its convenience, it opens up a new attack surface for hackers.

### Bluetooth : 

- `Bluesnarfing`: A cyber-attack involving unauthorised access to information from wireless devices through Bluetooth.
- `Bluejacking`: An attack that sends unsolicited messages to Bluetooth-enabled devices.
- `BlueSmacking`: A Denial-of-Service attack that overwhelms a device's Bluetooth connection.
- `Bluebugging`: A technique used to gain control over a device via Bluetooth.
- `BlueBorne`: A set of vulnerabilities that allow attackers to take control of devices, spread malware, or perform other malicious activities via Bluetooth.
- `KNOB` (Key Negotiation of Bluetooth): An attack that manipulates the data encryption process during Bluetooth connection establishment, weakening security.
- `BIAS` (Bluetooth Impersonation AttackS): This attack exploits a vulnerability in the pairing process, allowing an attacker to impersonate a trusted device.

### Side-Channel Attacks : 

- `Timing Attacks`: These exploit the correlation between the computation time of cryptographic algorithms and the secrets they process.
- `Power-Monitoring Attacks`: These monitor the power consumption of a device to determine what data it is processing.

### Microprocessor Vulnerabilities : 

- `Spectre` and `Meltdown`

## Introduction to Bluetooth : 

The technology operates by establishing `personal area networks` (PANs) using `radio frequencies` in the `ISM band from 2.402 GHz to 2.480 GHz`.

1. `Discovery`: One device makes itself `discoverable`, broadcasting its presence to other Bluetooth devices within range.
2. `Pairing Request`: A second device finds the discoverable device and sends a `pairing request`.
3. `Authentication`: The devices authenticate each other through a process involving a shared secret, known as a `link key` or `long-term key`. This may involve entering a PIN on one or both devices.
Once the devices are paired, they remember each other's details and can automatically connect in the future without needing to go through the pairing process again.

The Bluetooth specification identifies two types of links for data transfer:
1. `Synchronous Connection-Oriented (SCO) links`: Primarily used for audio communication, these links reserve slots at regular intervals for data transmission, guaranteeing steady, uninterrupted communication ideal for audio data.
2. `Asynchronous Connection-Less (ACL) links`: These links cater to transmitting all other types of data. Unlike SCO links, ACL links do not reserve slots but transmit data whenever bandwidth allows.

The array of risks associated with Bluetooth can be broadly classified into several categories:
1. `Unauthorised Access`: This risk involves unauthorised entities gaining unsolicited access to Bluetooth-enabled devices. Attackers can exploit vulnerabilities to take control of the device or eavesdrop on data exchanges, potentially compromising sensitive information and user privacy.
2. `Data Theft`: Bluetooth-enabled devices store and transmit vast amounts of personal and sensitive data. The risk of data theft arises when attackers exploit vulnerabilities to extract this data without authorisation. Stolen information may include contact lists, messages, passwords, financial details, or other confidential data.
3. `Interference`: Bluetooth operates on the 2.4 GHz band, which is shared by numerous other devices and technologies. This creates a risk of interference, where malicious actors may disrupt or corrupt Bluetooth communication. Intentional interference can lead to data loss, connection instability, or other disruptions in device functionality.
4. `Denial of Service (DoS)`: Attackers can launch Denial of Service attacks on Bluetooth-enabled devices by overwhelming them with an excessive volume of requests or by exploiting vulnerabilities in Bluetooth protocols. This can result in the targeted device becoming unresponsive, rendering it unable to perform its intended functions.
5. `Device Tracking`: Bluetooth technology relies on radio signals to establish connections between devices. Attackers can exploit this characteristic to track the physical location of Bluetooth-enabled devices. Such tracking compromises the privacy and security of device owners, potentially leading to stalking or other malicious activities.

![[Attacks.png]]
