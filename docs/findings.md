
---

### `docs/findings.md`

```md
# Findings

## Finding 1 — Telnet Exposed

**Port:** TCP/23

The camera has Telnet enabled.

Telnet provides remote access to the camera and increases the attack surface of the device.

### Risk

An exposed management service can provide an entry point to the device if authentication or other controls are weak.

### Recommendation

Disable Telnet if it is not required.

Use a secure management method where possible and restrict administrative access to authorised systems.

---

## Finding 2 — Weak Authentication

The camera uses weak/default credentials in the controlled lab environment.

### Risk

Weak credentials can allow unauthorised users to gain access to the device.

### Recommendation

Change default credentials before deployment and use a strong, unique password.

---

## Finding 3 — Legacy Web Interface

**Port:** TCP/81

The camera exposes an HTTP web interface.

The interface contains legacy web functionality and CGI endpoints used by the camera.

### Risk

Legacy web applications can contain outdated security controls and unnecessary functionality.

### Recommendation

Restrict access to the management interface and keep the device firmware updated where possible.

---

## Finding 4 — Multiple Exposed Services

The camera exposes more than one service.

### Risk

Each additional service increases the attack surface.

### Recommendation

Disable services that are not required and restrict access to management services using network controls.
