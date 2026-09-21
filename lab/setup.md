# Lab Setup

## Network

The lab uses an isolated private network:

`192.168.0.0/24`

Basic layout:

```text
Student Laptop
      |
      | Wi-Fi
      |
TP-Link Router
      |
Cisco Switch
      |
IP Camera
```

## Example Devices

| Device | IP Address |
|---|---|
| SCA_Router | 192.168.0.1 |
| SCA_Cisco_Switch | 192.168.0.101 |
| SCA_IP_CAM | 192.168.0.114 |

The exact IP address of the camera may change depending on the lab setup.

## Requirements

- Student laptop
- IP camera
- TP-Link router
- Managed Cisco switch
- Isolated network
- Python
- Nmap
- Web browser

## Basic Test

Check that the camera can be reached:

```bash
ping <CAMERA-IP>
```

Run network discovery:

```bash
nmap -n 192.168.0.0/24
```

Then enumerate the camera:

```bash
nmap -sV <CAMERA-IP>
```

The lab should only be used for authorised testing.
