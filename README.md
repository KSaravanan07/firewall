# Firewall

This project implements a custom firewall using Python to manage traffic between virtual machines (VMs) in a controlled environment. The firewall supports basic and advanced rule management across various layers, including Ethernet, IP, TCP, UDP, and ICMP, and is capable of detecting DoS attacks based on user-defined thresholds.

- K Saravanan (cs22mtech12007)

## Network Configuration and Setup

Three virtual machines are configured as follows:
- **VM1**: Acts as the internal network that needs protection.
- **VM2**: Acts as the firewall with two network interfaces.
- **VM3**: Acts as the external host connected to the internet.

### Network Connections
- **Network 1**: Connects VM1 and interface 1 of the firewall (VM2).
- **Network 2**: Connects VM3 and interface 2 of the firewall (VM2).
- VM3 is connected to the host via a bridge (e.g., 192.168.102.1) and can ping the internet.

## Task 1: Basic Firewall Setup
- Implemented in `simple_firewall.py`, which manages two network interface cards (NICs) to route traffic between internal and external networks.
- Traffic from the internal network to the external network is routed via the firewall, where MAC address manipulation occurs to forward packets correctly.

### Observations
- Packets from a specific IP (188.166.104.231) are dropped by the firewall, preventing them from reaching VM1.

## Task 2: Advanced Firewall Rules
- Implemented in `adv_firewall.py`, which allows adding, deleting, and updating rules at different protocol layers (Ethernet, IP, TCP, UDP, ICMP).
- Rules are managed through functions: `add_rule()`, `delete_rule()`, and `update_rule()`.
- Statistics and graphs are displayed using the `show_stat()` function, which shows the number of packets accepted/discarded over time.
- Rules are stored in `rule_file.json`.

### Features
- **Rule Management**: Add, update, or delete rules based on user input.
- **Traffic Monitoring**: Monitor TCP, UDP, and ICMP traffic, and visualize traffic statistics.
  
## Task 3: Performance Analysis
- Analyzed the packet processing capability (packets per second) of the firewall under various conditions.
- Performance degrades as the number of rules increases due to more time spent on field matching.
- **Performance Observations**:
  - Packet processing rate decreases as the number of rules increases.
  - Maximum packet handling observed with up to 100 rules.

## Task 4: DoS Attack Detection
- Implemented a DoS detection mechanism that monitors the frequency of incoming IP addresses.
- If an IP address exceeds a user-defined threshold, a DoS attack is detected.
- Includes alternative implementation considering time and threshold parameters for more robust detection.

### DoS Detection Cases
- **Case 1: DoS Detected**: Threshold set to 8; IP address exceeding this limit triggers detection.
- **Case 2: DoS Not Detected**: Threshold set to 20; no IP address crosses this limit.

## How to Run the Files

### Firewall VM Setup
1. Set up two network interface cards on the VM functioning as the firewall.
2. Link these NICs to VM1 (internal network) and VM3 (external network).

### VM1 (Internal Network) Configuration
1. Modify routes:
   - Delete the default route: 
     ```bash
     sudo route delete default
     ```
   - Add new route to the firewall:
     ```bash
     sudo route add default gw <IP_firewall_interface1>
     ```

### VM3 (External Network) Configuration
1. Modify routes:
   - Delete the default route:
     ```bash
     sudo route delete default
     ```
   - Add new route to the bridge:
     ```bash
     sudo route add default gw <IP_bridge>
     ```
   - Add new route to the firewall:
     ```bash
     sudo route add default gw <IP_firewall_interface2>
     ```

### Running the Firewall Scripts

#### Simple Firewall
To run the simple firewall script:
```bash
python3 simple_firewall.py <interface_name_1> <interface_name_2>
```
#### Advanced Firewall
To run the advanced firewall script:
```bash
python3 adv_firewall.py <interface_name_1> <interface_name_2>
```

Replace <interface_name_1> and <interface_name_2> with the names of the network interfaces that connect the firewall to the internal and external networks, respectively.
