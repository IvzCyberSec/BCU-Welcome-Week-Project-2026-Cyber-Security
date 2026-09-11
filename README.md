BCU Welcome Week — IP Camera Penetration Testing Lab

Overview

A beginner-friendly cybersecurity exercise designed for BCU Welcome Week.

Students act as junior cybersecurity specialists who have been asked to perform a basic penetration test against a deliberately isolated IP surveillance system before it is placed into production.

The exercise follows:

Discover → Enumerate → Identify → Test → Assess Risk → Defend

The aim is to introduce reconnaissance, service enumeration, authentication weaknesses, attack-surface analysis, and defensive thinking in a controlled environment.

Learning Objectives

By completing the exercise, students should be able to:

Understand the purpose of reconnaissance.

Discover devices on an isolated network.

Perform basic Nmap service enumeration.

Interpret ports and services.

Identify insecure or unnecessary services.

Recognise the risks of weak/default credentials.

Explain why exposed Telnet is a security concern.

Identify weaknesses in an IP surveillance system.

Recommend appropriate security controls and remediation.

Scenario

You have just been hired as a junior cybersecurity consultant for a small office.

The office has recently installed a new IP surveillance system. Before the system is placed into production, your job is to perform a basic penetration test and identify any security weaknesses.

The camera is located on a dedicated lab network. Your task is to discover the camera, identify its exposed services, investigate the available interface, test the supplied lab credentials, and explain how the weaknesses could be addressed.

Important: This is a deliberately isolated educational environment. Students must only test the systems provided for the exercise.

Lab Architecture

                         ┌─────────────────┐
                         │  TP-Link N300   │
                         │     Router      │
                         └────────┬────────┘
                                  │
                         ┌────────┴────────┐
                         │  Managed Cisco  │
                         │     Switch      │
                         └────────┬────────┘
                                  │
                           ┌──────┴──────┐
                           │  IP Camera  │
                           └─────────────┘

                         Wi-Fi connection
                                  │
                           ┌──────┴──────┐
                           │   Student   │
                           │    Laptop   │
                           └─────────────┘

Network

192.168.0.0/24

Students should use the addresses provided by the lab rather than assuming a particular device address.

Student Exercise

1. Reconnaissance

The first objective is to discover what devices are present on the lab network.

The provided custom Nmap scanner performs an initial network scan equivalent to:

nmap -n 192.168.0.0/24

The scanner presents discovered hosts to the student.

Student task

Identify the available devices and determine which one appears to be the IP camera.

Key concept: Before testing a service, you need to know what systems are actually present.

2. Select the Target

Once the available devices have been displayed, the student selects the IP camera as the target for further investigation.

The exercise then moves from broad reconnaissance to targeted enumeration.

3. Service Enumeration

The student performs service/version detection:

nmap -sV <target-ip>

The expected lab configuration exposes services including:

Port

Service

Purpose

23

Telnet

Remote administrative access

81

HTTP

Camera web interface

The exact Nmap output may vary depending on the camera and lab configuration.

Student questions

What services have been discovered?

Why might Telnet be a security concern?

Why should the web management interface be investigated?

Which services are actually required for the camera's intended purpose?

4. Web Interface

The student can access the camera web interface:

http://<target-ip>:81/

The lab provides intentionally weak credentials:

Username: admin
Password: admin

These credentials are deliberately supplied as part of the exercise.

Student questions

After logging in:

What level of access does the account provide?

What could an attacker potentially do if this were a real production device?

Why is a weak password dangerous?

What should the administrator change?

5. Identify the Weaknesses

Finding: Weak Administrative Credentials

Observation

The camera web interface accepts the supplied weak credentials:

admin / admin

Risk

Anyone able to reach the management interface and obtain the credentials may be able to authenticate and access camera functionality.

Potential impact

Depending on the device, unauthorised access could expose:

Live video

Camera configuration

PTZ controls

Network configuration

Device settings

Other administrative functionality

Recommendation

Replace default credentials.

Use a strong, unique password.

Restrict management access.

Avoid exposing camera management interfaces to untrusted networks.

Disable unused services.

6. Telnet

The Nmap scan also identifies Telnet on port 23.

Students should understand that Telnet is an insecure remote administration protocol and should not normally be exposed on a production surveillance device.

Discussion questions

Why is Telnet considered insecure?

What would be a safer alternative?

Should the camera need remote shell access at all?

How could network segmentation reduce the risk?

What would happen if an attacker discovered valid credentials?

The exercise focuses on the security implications rather than requiring extensive post-access activity.

7. Defence

The final stage changes the student's role from attacker to defender.

Students should propose how the camera could be secured before production deployment.

Authentication

Replace default credentials.

Use strong, unique passwords.

Avoid shared administrator accounts.

Change credentials before deployment.

Network Security

Place cameras on a dedicated VLAN.

Restrict access to camera management interfaces.

Use firewall rules or ACLs to limit management traffic.

Prevent unnecessary access from user networks.

Services

Disable Telnet.

Disable unnecessary services.

Expose only services required by the camera.

Device Security

Keep firmware updated where supported.

Replace unsupported legacy devices.

Review manufacturer security guidance.

Monitoring

Log authentication attempts.

Monitor unexpected network connections.

Alert on unusual management activity.

Penetration-Testing Methodology

RECONNAISSANCE
      ↓
Discover devices
      ↓
ENUMERATION
      ↓
Identify services
      ↓
IDENTIFICATION
      ↓
Understand the target
      ↓
CONTROLLED TEST
      ↓
Test supplied access
      ↓
RISK ASSESSMENT
      ↓
Explain the impact
      ↓
DEFENCE
      ↓
Recommend fixes

Custom Student Scanner

The lab uses a custom Python-based Nmap scanner to make reconnaissance accessible to beginners.

The scanner is designed to:

Scan the complete lab subnet.

Display discovered hosts.

Allow the student to select a target.

Run service/version enumeration against the selected target.

Present the results in a beginner-friendly format.

The scanner is intentionally tailored to the exercise rather than requiring students to construct every Nmap command themselves.

Example workflow

Start scanner
     ↓
Network discovery
     ↓
192.168.0.0/24
     ↓
Available devices displayed
     ↓
Student selects camera
     ↓
Service enumeration
     ↓
Ports/services displayed
     ↓
Student investigates findings

Expected Student Findings

A successful student should be able to identify:

Camera IP address

Discovered during network reconnaissance.

HTTP service

TCP/81

Telnet service

TCP/23

Weak credentials

admin / admin

Security recommendations

Students should recommend measures such as:

Strong unique credentials.

Disabling Telnet.

Network segmentation.

Restricting management access.

Removing unnecessary services.

Firmware updates or replacement of unsupported equipment.

What Students Are NOT Being Asked To Do

This is an introductory exercise.

Students are not expected to:

Attack systems outside the lab.

Scan the public Internet.

Attempt to compromise unrelated devices.

Perform denial-of-service attacks.

Modify or destroy camera data.

Persist on the device.

Evade detection.

Attack other students' systems.

The purpose is to understand the basic penetration-testing process and learn how vulnerabilities translate into defensive requirements.

Safety and Scope

This project is intended for a controlled, isolated cybersecurity teaching environment.

The lab should remain isolated from the Internet and production networks.

Students should only target systems explicitly authorised by the exercise.

Learning Outcome

The key lesson is:

Discover what exists → understand what is exposed → identify the weakness → assess the risk → explain how to fix it.

The goal is to introduce students to the mindset of a cybersecurity professional while keeping the technical barrier low enough for a Welcome Week activity.

Project Context

The physical lab consists of:

TP-Link N300 router

Managed Cisco switch

IP camera

Student laptop connected to the router over Wi-Fi

Custom Python/Nmap student scanner

The environment is designed to provide students with a realistic but contained introduction to penetration testing.

Disclaimer

This project is for educational and authorised lab use only.

Do not use the techniques, commands, or methodology described here against systems that you do not own or have explicit permission to test.
