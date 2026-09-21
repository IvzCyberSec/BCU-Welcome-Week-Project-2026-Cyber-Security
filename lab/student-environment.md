
### `lab/student-environment.md`

```md
# Student Environment

## Scenario

You have been hired as a junior cybersecurity consultant.

A small office has installed a new IP surveillance system. Before the camera is placed into production, you have been asked to perform a basic security assessment.

Your job is to find out:

- What devices are on the network?
- What services are exposed?
- What is running on those services?
- Are there any obvious security weaknesses?
- How could the device be made more secure?

## Starting Point

You are given access to the isolated lab network.

You are not given the camera IP address.

Start with network discovery:

```bash
nmap -n 192.168.0.0/24
