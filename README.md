# Secure Storage in Edge-Cloud MPU-based Simulation

## Overview
This project is a Python/FastAPI simulation of a secure edge-cloud storage system.

The system contains:
- **Edge nodes** (`edgeA`, `edgeB`, `edgeC`) that encrypt data locally
- **Cloud server** (`cloud`) that stores encrypted backups

The main goal is to simulate a security-focused storage architecture where the cloud stores only **ciphertext**, while decryption happens only on the edge node.

## Core Idea
The edge node:
1. takes local plaintext data
2. encrypts it locally using a symmetric key
3. signs requests using its private key
4. uploads only encrypted data to the cloud

The cloud:
1. verifies node identity and signatures
2. checks nonce and timestamp freshness
3. stores encrypted backups
4. returns encrypted backups to authenticated edge nodes

This means the cloud acts as **blind storage**: it stores the backup but does not read plaintext.

## Security Features
- **Local encryption before upload**
- **Ed25519 digital signatures** for node authentication
- **Fernet symmetric encryption** for local vault protection
- **SHA-256 integrity hash**
- **Nonce + timestamp** for replay protection
- **Audit logging** on both edge and cloud sides

## Architecture
### Edge side
Each edge node:
- has an Ed25519 key pair
- has a Fernet key
- encrypts local data
- signs backup and recovery requests
- decrypts recovered ciphertext locally

### Cloud side
The cloud:
- stores registered node public keys
- verifies signatures
- stores ciphertext backups
- never decrypts data
- keeps access logs

## Project Structure
```text
SS_project/
├── app/
│   ├── audit.py
│   ├── cloud_service.py
│   ├── config.py
│   ├── crypto_utils.py
│   ├── edge_service.py
│   ├── integrity.py
│   ├── models.py
│   └── storage.py
├── data/
│   ├── edgeA/
│   ├── edgeB/
│   ├── edgeC/
│   └── cloud/
├── setup.py
└── README.md