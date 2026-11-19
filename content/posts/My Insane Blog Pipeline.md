---
title: "Hands-on Lab: Advanced Isolation and Confinement on Linux"
date: 2026-11-19T12:00:00+00:00
draft: false
description: "Learn how to isolate and confine processes on Linux with capabilities, seccomp, namespaces, cgroups and AppArmor, then harden a Docker container and audit it with Trivy and Falco."
categories: ["System Administration", "Security"]
tags: ["Linux", "Docker", "Capabilities", "Seccomp", "AppArmor", "Namespaces", "cgroups", "Trivy", "Falco", "LoveIt"]
lightgallery: true
---
![Isolation Linux sécurisée futuriste](/images/isolation-linux.png)

## 1. Introduction and Lab Objectives

On a Linux server, the classic permission model (owner, group, others) is not enough to contain a compromised process. The `root` user ignores it, and it only says *who* can act, never *what* a program is allowed to do.

In this lab for **SenTech Solutions**, we isolate our processes with several complementary mechanisms.

The objectives are to:
- Understand the limits of DAC and why MAC (Mandatory Access Control) is needed.
- Break root's privileges into small pieces with **capabilities**.
- Restrict system calls with **seccomp**.
- Isolate what a process sees (**namespaces**) and what it consumes (**cgroups**).
- Confine programs with **AppArmor**.
- Harden a Docker container and audit its image with **Trivy**.
- Understand a container escape in order to prevent it, and detect intrusions with **Falco**.

---

## 2. Prerequisites and Environment Preparation

Docker runs applications as containers: isolated processes with their own namespaces and a limited set of capabilities. We start by checking that Docker works:

```bash
sudo docker run hello-world
```

Then we install the tools used throughout the lab:
- `libcap2-bin`: manages Linux capabilities.
- `apparmor-utils`: manages AppArmor (a MAC system). AppArmor restricts what a program can access, regardless of who runs it.
- `gcc`: the GNU Compiler Collection.
- `stress-ng`: a powerful tool to stress-test subsystems of an OS (CPU, memory, I/O).

```bash
sudo apt install libcap2-bin apparmor-utils gcc stress-ng
```

---

## 3. From DAC to MAC

### 3.1 The limits of the DAC model

With **DAC (Discretionary Access Control)**, the owner of a file decides who can read or write it (`chmod`, `chown`, ACLs). The main problem: `root` ignores DAC and can override every permission. DAC says *who* can act, but not *what* a program has the right to do. For example, a root process can easily read `/etc/shadow`.

That is why **MAC** is put in place: it restricts what a program can access, regardless of who runs it. In practice, we use both DAC and MAC.

---

## 4. Breaking Down Root Privileges with Capabilities

Capabilities are a Linux kernel feature that splits root's privileges into small, distinct, and independent permissions.

### 4.1 Observing capabilities

Let's look at the capability of `ping`:

```bash
getcap "$(which ping)"
```

![ping capability](/images/ping-capability.png)

You will see `cap_net_raw`. This capability allows `ping` to work, and on recent Ubuntu versions `ping` relies on it instead of running as SUID root.

Now we inspect the capabilities of our current shell. `Current: =` means the process currently holds no active capabilities.

![shell capabilities](/images/shell-capabilities.png)

### 4.2 Allowing a port below 1024 without root

Only `root` can bind to port 80. Instead of giving a process root, we give it the single capability it needs: `cap_net_bind_service`.

First, a small C program that tries to listen on port 80:

```bash
cat > ~/bind80.c <<'EOF'
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;

    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(80);
    a.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(s, 1) < 0) {
        perror("listen");
        return 1;
    }

    printf("Ecoute sur le port 80 (PID %d) - Ctrl+C pour quitter\n", getpid());
    pause();

    return 0;
}
EOF
gcc ~/bind80.c -o ~/bind80
```

The program asks the kernel: *"I want to bind to port 80."* The kernel checks the process's Effective Capabilities (`CapEff`). Our shell has zero capabilities, so the kernel answers `permission denied`.

![bind denied](/images/bind-denied.png)

Now we grant the capability to the program so it can bind as a normal user, without root:

```bash
sudo setcap 'cap_net_bind_service=+ep' ~/bind80
getcap ~/bind80
```

![setcap](/images/setcap.png)

`CAP_NET_BIND_SERVICE` gives the process only what it needs to bind to port 80. Running it as root would have given it full access, and if compromised, an attacker could reach sensitive files.

{{< admonition warning "The most dangerous capability" >}}
`CAP_SYS_ADMIN` is often called "the new root": it grants a process access to a massive array of dangerous operations.
{{< /admonition >}}

---

## 5. Seccomp: Filtering System Calls

### 5.1 Concept

**Seccomp** (secure computing mode) is a Linux kernel feature that restricts the actions a process can take by filtering the system calls it is allowed to make. When a program needs to open a file, create a process, or mount a filesystem, it makes a syscall to the kernel. With seccomp, we define a list of authorised syscalls, and anything outside the list is blocked.

### 5.2 Confining an active service with systemd

The service is denied the call even when run with `sudo`. The reason is in the directive:
- `SystemCallFilter=~@mount` means: allow everything normally, **except** the syscalls in the `@mount` group.
- `SystemCallFilter=@mount` would mean the opposite: allow **only** the syscalls in the `@mount` group, and block all the others.

### 5.3 Measuring a service's exposure

We analyse the `ssh` service with `systemd` to see how exposed it is.

![ssh exposure 1](/images/ssh-exposure-1.png)
![ssh exposure 2](/images/ssh-exposure-2.png)

Two syscall families that a web server has no reason to use:
- `@reboot`: the calls that allow restarting or shutting down the machine.
- `@module`: the calls that load, unload, or manipulate Linux kernel modules.

---

## 6. Isolation with Namespaces and cgroups

- **Namespaces** isolate what a process sees: `PID`, `NET`, `MNT`, `UTS`, `USER`.
- **cgroups** limit what a process consumes: CPU, memory.

### 6.1 Building a container with unshare

`unshare` is a powerful command-line tool that isolates processes in new namespaces: you tell the kernel to detach the current process from the host's namespaces.

![unshare](/images/unshare.png)

Inside the new namespace, the shell appears as `root` with PID 1, and we only see `bash` and `ps`. *(Running this with `sudo` is acceptable only for this demonstration.)*

### 6.2 Isolating the hostname (UTS namespace)

![UTS namespace](/images/uts-namespace.png)

Inside the "container" we changed the hostname to `conteneur-sentech`. It only applies inside the container: when we exit, the real hostname is unchanged. Everything stays in the container.

### 6.3 Listing and inspecting namespaces

![namespaces](/images/namespaces.png)

### 6.4 Capping resources with cgroups

![cgroups](/images/cgroups.png)

---

## 7. Mandatory Access Control with AppArmor

AppArmor is the default MAC system on Ubuntu. A profile lists the files and operations that are authorised; everything not in the list is refused, even for `root`.

A profile has two modes:
- **Complain mode:** prohibits nothing, but logs what would have been refused.
- **Enforce mode:** blocks and logs the prohibited actions.

### 7.1 Confining access and checking that MAC dominates root

In complain mode, we can read the confined file and also `/etc/shadow`, because we run with `sudo` and nothing is blocked. However, the prohibited actions are recorded in `journalctl`.

![complain mode](/images/complain-mode.png)
![journalctl](/images/journalctl.png)

After switching the profile to enforce mode, access to `/etc/shadow` is now denied.

![enforce mode](/images/enforce-mode.png)

Everything is logged in the audit log, so we can see exactly what happened.

**Why DAC alone would not have prevented it:** DAC relies on the file owner's permissions, and a `sudo` user can bypass them. MAC defines what the program can access, regardless of who runs it, even a `sudo` user.

---

## 8. Securing a Docker Container

We run a container with `sh` and check which user it runs as.

![container user](/images/container-user.png)

### 8.1 Default protections

Modern Linux applies a default AppArmor profile to containers, even without any configuration. We verify it:

![docker apparmor](/images/docker-apparmor.png)

Seccomp also protects by default. We check that it blocks dangerous syscalls such as `unshare`, used to create a namespace:

![docker seccomp](/images/docker-seccomp.png)

`"Operation not permitted"` means the kernel rejected the syscall.

Next, we run the container with seccomp unconfined:

![seccomp unconfined](/images/seccomp-unconfined.png)

This only stops blocking syscalls like `unshare` or `mount`. The kernel also checks Linux capabilities before allowing a process to modify mounts, so even though the `mount` syscall was allowed to run, the kernel rejected it because the container lacks the administrative privileges. This is **defense in depth**.

### 8.2 Building the hardened image

```bash
mkdir -p ~/webapp && cd ~/webapp
cat > app.py <<'EOF'
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write("SenTech WebApp - conteneur durci\n".encode())

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
EOF
```

This script creates a web server that answers any GET request with an HTTP `200 OK` and the plain-text message `SenTech WebApp - conteneur durci`.

We then put the web server in a container so it does not run on the host, give it a dedicated user ID so it never runs as root, and apply a custom seccomp profile. The profile uses `SCMP_ACT_ERRNO`: everything is allowed except the syscalls in the list (a blacklist).

![build image](/images/build-image.png)

### 8.3 Running the hardened container

![run hardened](/images/run-hardened.png)

All mechanisms are applied to the container:

| Option | Effect |
| :--- | :--- |
| `--read-only` | The whole root filesystem is read-only. Even if an attacker executes code, they cannot write malware. |
| `--cap-drop=ALL` | Zero kernel capabilities: all privileges are blocked. |
| `--security-opt=no-new-privileges` | A process cannot gain higher privileges (for example via setuid). |
| `--security-opt apparmor=docker-default` | MAC: restricts the system paths and resources the container can touch. |
| `--memory=128m`, `--cpus=0.5` | Resource guardrails. |

### 8.4 Testing the hardening

![hardening tests](/images/hardening-tests.png)

Every attempted action is denied.

---

## 9. Image Hygiene: Analysis with Trivy

**Trivy** acts as an automated vulnerability detector. It scans a target for known security issues: outdated packages, software flaws, and dangerous configuration choices. It combines static binary analysis with an up-to-date vulnerability database.

```bash
trivy image nginx:1.14
```

Result for `nginx:1.14`:
- **Critical: 31.** Flaws that are typically exploitable remotely and can lead to immediate compromise.
- **High: 82.** Serious flaws that can let attackers escalate privileges or leak sensitive data.
- **Remediation:** update the base image and run a package upgrade in the build stage.

![trivy scan 1](/images/trivy-scan-1.png)
![trivy scan 2](/images/trivy-scan-2.png)

Second scan: **High 67, Critical 1**.

![trivy scan 3](/images/trivy-scan-3.png)

Third scan: **High 49, Critical 0**. The 49 High findings can still allow privilege escalation or sensitive data leaks.

For misconfigurations, we use:

```bash
trivy config ~/webapp
```

Out of 28 tests, only 1 failed, which is very low.

![trivy config](/images/trivy-config.png)

{{< admonition note "What is a CVE?" >}}
**CVE** stands for *Common Vulnerabilities and Exposures*. Imagine a software library has a flaw that lets an attacker execute malicious code. When the vulnerability is publicly documented, it can receive a CVE identifier, for example `CVE-2021-44228`.

Trivy maps vulnerabilities into five severity tiers: `UNKNOWN (0)`, `LOW (1)`, `MEDIUM (2)`, `HIGH (3)`, `CRITICAL (4)`.
{{< /admonition >}}

---

## 10. Understanding to Prevent: Container Escape

This section reproduces a misconfiguration in order to gauge the associated danger and learn how to prevent it. It takes place exclusively within the lab environment. No new offensive techniques are presented here, only configurations that are already publicly documented as dangerous.

### 10.1 The concept

A container shares the host's kernel. Its isolation relies solely on the mechanisms described above (capabilities, seccomp, namespaces, AppArmor). Breaking just one of them can be enough to "break out" to the host. Here we reproduce one common misconfiguration: mounting the host filesystem inside a container.

### 10.2 Controlled demonstration: reading files from the host

We run a container that mounts the host filesystem at `/host`, read-only:

```bash
sudo docker run --rm -it -v /:/host:ro alpine sh
```

![host mount](/images/host-mount.png)

Even though the mount is read-only (`:ro`), the container can read sensitive host data. Normally a container should only see the files it needs to run its application, but this command gave it access to almost the entire host filesystem. That is exactly what an attacker looks for after compromising a containerized application: the mechanism bypasses the mount namespace and exposes the host files inside the container.

---

## 11. Detecting Intrusions at Runtime with Falco

**Falco** is an open-source runtime security tool. It watches Linux kernel events such as system calls in real time, to detect suspicious or abnormal behavior across containers, and raises an alert when something unexpected happens.

After running the web container, we try:

```bash
sudo cat /etc/shadow > /dev/null
```

On the other side, Falco sends an alert.

![falco alert](/images/falco-alert.png)

---

## 12. Conclusion

No single mechanism is enough. Each layer limits a different thing, and together they give **defense in depth**:

| Mechanism | What it limits |
| :--- | :--- |
| **DAC + MAC** | Who can access, and what a program can access |
| **Capabilities** | Which parts of root's power a process holds |
| **Seccomp** | Which system calls a process can make |
| **Namespaces** | What a process can see |
| **cgroups** | What a process can consume |
| **AppArmor** | Which files and operations a program may use, even as root |
| **Trivy** | Known vulnerabilities and misconfigurations in images |
| **Falco** | Suspicious behavior at runtime |