# Methodology

The assessment follows a simple security testing process.

## 1. Reconnaissance

Identify devices on the local network.

Example:

```bash
nmap -n 192.168.0.0/24
```

## 2. Enumeration

Scan the identified camera for open ports and services.

Example:

```bash
nmap -sV <CAMERA-IP>
```

## 3. Identification

Look at the services that are exposed and determine what they are used for.

In this lab, the camera exposes Telnet and HTTP.

## 4. Investigation

Investigate the services in the authorised lab environment.

This includes looking at the web interface and, where permitted by the exercise, investigating the embedded system and its files.

## 5. Evidence

Record useful information such as:

- IP addresses
- Open ports
- Service information
- Screenshots
- Relevant files
- Security observations

## 6. Assessment

Consider what the findings mean from a security perspective.

Ask:

- What could an attacker access?
- Why is the service exposed?
- Is authentication strong?
- Is the service still required?

## 7. Remediation

Recommend practical controls to reduce the risk.

The assessment should finish with defensive recommendations rather than simply identifying the weakness.
