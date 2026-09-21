# BCU Welcome Week — IP Camera Security Assessment Lab

A hands-on cybersecurity project developed for the **SCA Cyber Security Community at Birmingham City University**.

This project takes a real embedded IP camera and turns it into a controlled security assessment lab for students. The lab follows the same general progression used during my own investigation of the device: **network reconnaissance, service enumeration, authorised access, embedded-system investigation, web application analysis, evidence gathering, and remediation**.

The project also includes a custom Python scanner and a custom SecureCam web interface developed specifically for the lab.

---

## Project Overview

The scenario is based around a small office that has installed a new IP surveillance system.

Before the camera is placed into production, students are asked to perform a basic security assessment and identify weaknesses that could create risk.

The exercise follows:

**Discover → Enumerate → Identify → Investigate → Assess Risk → Defend**

The environment is isolated and intended only for authorised educational testing.

---

# My Technical Investigation

The project began with a practical investigation of the camera rather than simply designing a theoretical exercise.

### 1. Network Reconnaissance

I started by performing network discovery across the isolated lab network:

```bash
nmap -n 192.168.0.0/24
```

This allowed me to identify the devices present on the network and locate the IP camera.

Once the camera was identified, I performed targeted service enumeration:

```bash
nmap -sV <TARGET-IP>
```

The camera exposed services including:

- **TCP/23 — Telnet**
- **TCP/81 — HTTP**

This provided the initial attack surface for further investigation.

---

### 2. Authorised Telnet Access

After identifying Telnet as an exposed service, I connected to the camera through the Telnet interface within the isolated lab environment.

The investigation demonstrated the security implications of legacy remote administration and weak/default authentication on embedded devices.

After gaining authorised administrative access, I was able to investigate the underlying operating environment rather than treating the camera purely as a web interface.

---

### 3. Embedded Linux / BusyBox Investigation

The camera runs an embedded Linux environment using **BusyBox**.

From the Telnet shell, I investigated the filesystem and identified the camera's web application directory:

```text
/system/www
```

This was an important point in the investigation because it provided access to the files responsible for the camera's web interface.

Rather than stopping after obtaining shell access, I used the access to understand how the device itself was built and how its web functionality worked.

---

### 4. Extracting the Camera's Web Application

I identified the camera's available **TFTP functionality** and configured a TFTP server on my Windows analysis workstation.

This allowed me to transfer the relevant web application files from the camera to my PC for offline investigation.

The process involved:

```text
Camera
   ↓
Telnet / BusyBox shell
   ↓
/system/www
   ↓
TFTP transfer
   ↓
Windows analysis workstation
   ↓
Offline file analysis
```

This gave me a local copy of the camera's web application components without needing to repeatedly work directly on the embedded device.

The extracted material included the HTML and JavaScript used by the original interface, along with the relevant camera web functionality.

---

### 5. Web Application Analysis

I then analysed the extracted files to understand how the original camera interface operated.

This involved following the HTML and JavaScript used by the interface and identifying the underlying functionality exposed by the camera.

The investigation included:

- Login behaviour
- Web interface navigation
- Camera viewing modes
- JavaScript functions
- CGI endpoints
- Authentication parameters
- Video-stream functionality
- The relationship between the front-end interface and the embedded camera services

One of the important findings was the camera's video-stream functionality and the way the original interface constructed requests to the stream endpoint.

This investigation allowed me to move from simply identifying an HTTP service to understanding what the service was actually doing.

---

# Custom SecureCam Interface

After understanding the original web application, I developed a new custom interface for the Welcome Week lab.

The purpose was not simply to redesign the camera visually. The interface was created using the functionality I had investigated in the original application and adapted for the educational environment.

The custom interface includes:

- BCU branding
- SCA Cyber Security Community branding
- Camera viewing functionality
- PTZ controls
- Lab-specific information
- Local assets
- Offline operation suitable for the isolated lab
- A simplified interface for students

The page is hosted directly from the camera's web environment and is designed to operate without relying on external internet resources.

---

## AI-Assisted Development

AI tools were used as a **development and implementation aid** while creating the custom interface and supporting code.

The important distinction is that the AI-assisted development came **after the technical investigation**.

I first:

1. Discovered the camera
2. Enumerated its services
3. Identified Telnet and HTTP
4. Gained authorised access in the isolated lab
5. Investigated the BusyBox environment
6. Located `/system/www`
7. Transferred the web files to my workstation
8. Analysed the original HTML and JavaScript
9. Identified the relevant camera functionality
10. Used those findings to guide development of the new interface

AI was then used to help implement and refine the custom interface.

This means the project demonstrates both **hands-on security investigation** and the practical use of AI-assisted development.

---

# Custom Python Security Scanner

To turn the investigation into a usable Welcome Week exercise, I also developed a custom Python scanner.

The scanner provides a simplified workflow for students:

```text
Discover
   ↓
Select Target
   ↓
Enumerate Services
   ↓
Identify Device
   ↓
Investigate
```

The scanner includes:

- Local network discovery
- TCP port scanning
- Service checks for relevant lab ports
- Device identification
- Colour-coded findings
- Beginner-friendly terminal output
- Camera-specific guidance
- Browser integration
- Reusable scan workflow

The tool is deliberately designed around the learning objective rather than attempting to replace Nmap.

---

# Security Findings

The investigation demonstrated several security issues associated with the legacy camera.

### Exposed Telnet

TCP/23 provided remote administrative access to the embedded device.

Legacy remote administration services such as Telnet increase the attack surface and do not provide the protections expected from modern secure management protocols.

### Weak / Default Authentication

The controlled lab demonstrated the risk created by weak or default credentials.

An embedded device deployed with unchanged credentials can provide an attacker with a route to administrative functionality.

### Legacy Web Application

The camera exposes an HTTP management interface on TCP/81.

The application contains legacy web functionality and CGI endpoints related to camera operation and video streaming.

### Embedded Device Attack Surface

The combination of remote administration, a web interface and additional camera functionality demonstrates why embedded devices need to be assessed as complete systems rather than simply checking whether a port is open.

---

# Remediation

The assessment finishes with defensive recommendations.

Potential controls include:

- Disable Telnet where it is not required
- Replace legacy management protocols with secure alternatives
- Change default credentials before deployment
- Use strong, unique administrative passwords
- Restrict management access to authorised hosts
- Segment cameras and other IoT devices from normal user networks
- Restrict unnecessary inbound traffic with firewall rules
- Keep firmware updated where vendor support exists
- Remove unnecessary services
- Monitor administrative access and unusual network activity
- Replace unsupported hardware where appropriate

The correct remediation depends on the device, firmware and operational requirements.

---

# Lab Infrastructure

The physical environment consists of:

```text
                    TP-Link N300 Router
                            |
                    Managed Cisco Switch
                            |
                        IP Camera

                    Wi-Fi / Network Access
                            |
                      Student Laptop
```

Example private addressing:

| Device | Example Address | Purpose |
|---|---:|---|
| SCA_Router | `192.168.0.1` | Network gateway |
| SCA_Cisco_Switch | `192.168.0.101` | Switch management |
| SCA_IP_CAM | `192.168.0.114` | Target IP camera |
| Dell Laptop | DHCP / lab assigned | Assessment workstation |

Real credentials and sensitive environment-specific information should not be committed to a public repository.

---

# Evidence and Documentation

The project is designed around evidence-based assessment.

Useful evidence includes:

- Network discovery output
- Service enumeration output
- Open service identification
- Telnet access evidence
- Embedded-system investigation
- Extracted web application files
- Web application analysis
- Camera interface screenshots
- Security findings
- Remediation recommendations

This provides a clear record of how a finding was discovered and how its security implications were assessed.

---

# Repository Structure

```text
bcu-welcome-week-ip-camera-pentest/
│
├── README.md
│
├── scanner/
│   ├── scanner.py
│   └── requirements.txt
│
├── lab/
│   ├── network-topology.png
│   ├── physical-setup.png
│   ├── setup.md
│   └── student-environment.md
│
├── evidence/
│   ├── reconnaissance.png
│   ├── enumeration.png
│   ├── camera-interface-accessed.png
|   ├── camera-interface-login.png
│   └── tftp-camera-dump.png
|
├── custominterface/
│   ├── securecam.html
│   ├── bcu_logo.png
│   ├── sca_logo.png
│   └── sca_qr.png
│
└── docs/
    ├── findings.md
    ├── remediation.md
    └── methodology.md
```

---

# Technology Used

### Security / Networking

- Nmap
- TCP/IP
- HTTP
- Telnet
- Network reconnaissance
- Service enumeration
- Embedded-device security investigation

### Development

- Python
- HTML
- JavaScript
- Linux / BusyBox shell
- Web application analysis
- AI-assisted development

### Lab Infrastructure

- IP surveillance camera
- TP-Link router
- Managed Cisco switch
- Isolated private network
- Windows workstation
- TFTP server
- Student laptops

---

# What This Project Demonstrates

This project demonstrates a practical end-to-end security workflow rather than a collection of isolated commands.

### Security Assessment

- Network discovery
- Service enumeration
- Attack-surface identification
- Authentication assessment
- Embedded-device investigation
- Web application analysis
- Evidence collection
- Remediation planning

### Technical Development

- Python security tooling
- HTML and JavaScript development
- Embedded Linux investigation
- TFTP-based file transfer
- Analysis of legacy web applications
- Custom interface development
- AI-assisted implementation

### Practical Security Skills

The project required me to move between different layers of the environment:

**Network → Services → Authentication → Shell → Filesystem → Web Application → CGI → Video Stream**

That progression was particularly useful because it showed how information gathered during one stage of an assessment can be used to guide the next.

---

# Portfolio Relevance

This project demonstrates experience relevant to several cybersecurity roles, including:

- SOC Analyst
- Vulnerability Assessment
- Penetration Testing
- Network Security
- Security Engineering
- IoT Security
- Cybersecurity Consulting

The main value of the project is the complete investigation process.

I did not simply identify an open port. I used the exposed services to investigate the device, obtained authorised access within the lab, examined its embedded operating environment, extracted and analysed its web application, identified how its functionality worked, developed a custom interface based on those findings, and then turned the investigation into a repeatable student security lab.

---

# Responsible Use

This project is intended for:

- University cybersecurity education
- Controlled security labs
- Authorised security testing
- Security awareness activities
- Personal cybersecurity learning

Do not use the scanner, techniques or access methods demonstrated here against systems without explicit permission.

The camera environment used for development and demonstration is isolated from production systems.

---

# Project Status

**Status:** Active Educational / Portfolio Project

Developed as part of practical cybersecurity work with the **SCA Cyber Security Community at Birmingham City University**.

Future development may include additional simulated devices, expanded defensive exercises, improved assessment reporting and further student challenges.

---

# Author

**Ivan**  
Cyber Security Student  
Birmingham City University

Developed as a practical cybersecurity and education project for the SCA Cyber Security Community.

---

## Disclaimer

This repository contains material intended for authorised educational and security testing environments.

Only use the techniques and tooling against systems where you have explicit permission to perform security testing.
