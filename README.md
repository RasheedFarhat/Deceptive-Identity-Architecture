# Deceptive-Identity-Architecture
A self-hosted, identity deception architecture integrating Authentik SSO with Canarytokens and automated threat telemetry
# Zero-Trust Architecture: Identity Provisioning and Active Defense Telemetry

## Executive Summary
A dual-phase security engineering project demonstrating proficiency in Identity and Access Management (IAM) and Active Defense. This project involves the deployment of a centralized Identity Provider to establish a strict access perimeter, alongside the engineering of a self-hosted deception engine and custom telemetry aggregator. The architecture successfully shifts intrusion detection away from noisy network perimeters toward high-fidelity, identity-centric traps.

## Architectural Overview
This project is divided into two distinct environments to simulate the "Preventative" and "Detective" layers of a modern enterprise network:

1. **The Identity Perimeter (macOS / ARM64 Host):** Deployment of Authentik as a centralized Single Sign-On (SSO) provider. This serves as the preventative front door, enforcing access policies and authenticating users for simulated corporate applications.
2. **The Active Defense Fabric (Kali Linux / AArch64 VM):** A self-compiled Canarytokens deception engine paired with a custom Python microservice. This serves as the detective backend, generating zero-false-positive alerts and automatically enriching threat telemetry when an adversary interacts with fabricated credentials or embedded web bugs.

## Core Components
* **Identity Provider:** Authentik (Docker Compose, natively deployed on Apple Silicon)
* **Deception Engine:** Canarytokens (Self-compiled from source for AArch64)
* **Telemetry Aggregator:** Custom Python/Flask microservice for alert ingestion and routing
* **Threat Enrichment:** AbuseIPDB API integration for real-time geographic and ISP analysis
* **Network Tunneling:** SSH reverse tunnels (localhost.run / Ngrok) utilized to securely route external HTTP callbacks into the local virtualized environment.

## Key Technical Achievements
* **Advanced Containerization:** Overcame macOS VirtioFS UID/GID mapping conflicts and Docker socket permission errors to stabilize the Authentik database initialization on Apple Silicon.
* **Native ARM64 Compilation:** Bypassed Rosetta emulation by manually compiling the complex, database-backed Canarytokens infrastructure from source code against the AArch64 kernel.
* **Cryptographic Troubleshooting:** Diagnosed and resolved base64 padding and byte-length initialization failures within the backend WireGuard token generation module.
* **SSRF Evasion & Traffic Routing:** Successfully bypassed the deception engine's strict Server-Side Request Forgery (SSRF) protections by establishing secure reverse tunnels to route webhook validation pings.
* **Header Extraction Logic:** Engineered a regex engine within the Python Flask listener to strip proxy IP addresses and extract the true external IPv4/IPv6 source address from raw HTTP headers for accurate threat enrichment.

## Repository Structure
* `/authentik-infrastructure`: Centralized IdP Docker Compose deployments, `.env` templates, and VirtioFS volume mapping configurations.
* `/deception-infrastructure`: Heavily modified Canarytokens build files, customized port listener mappings, and secure cryptographic seed configurations.
* `/telemetry-fabric`: Python/Flask webhook listener source code, reverse tunnel setup scripts, and AbuseIPDB API enrichment logic.
