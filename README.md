# Fed-EALE

**Fed-EALE: Efficient Authentication With Lightweight Encryption for Federated Learning in Vehicular Ad-Hoc Networks Using SSI**

This repository contains the implementation of the Fed-EALE framework, which integrates lightweight encryption and zero-knowledge proofs (ZKPs) for secure and efficient federated learning (FL) in vehicular ad-hoc networks (VANETs), leveraging Self-Sovereign Identity (SSI).

## 📘 Overview

Fed-EALE combines:
- **Federated Learning (FL)** for collaborative model training without raw data exchange.
- **Zero-Knowledge Proofs (ZKPs)** for privacy-preserving authentication.
- **Self-Sovereign Identity (SSI)** for decentralized identity management.
- **Lightweight encryption** for reducing overhead in resource-constrained vehicular environments.

## 📁 Project Structure
Fed-EALE/
- ├── circom_1/ # ZKP-based authentication circuits using circom
- ├── dataset/ # A123 SOC dataset for FL model training and evaluation
- ├── factor_t_4/ # ZKP identity authentication implementation with circom
- ├── ZKP_Auth/ # Evaluation: FL performance, overhead, blockchain access


### 🔐 `circom_1/`

- Contains zero-knowledge proof circuits for identity authentication built using [circom].
- **Key Script**: `ZKPcircom_1.py` – run this to test and invoke the ZKP circuits.

### 🔐  `dataset/ `
- Contains A123 lithium-ion battery datasets: DST, FUDS, and US06 cycles at 10°C to 50°C.
- Used for state of charge (SOC) estimation in the federated learning setting.

### 🔐  `factor_t_4/`
- Implements an ZKP-based identity authentication circuit using circom.

### 🔐  `ZKP-Auth/`
Includes comprehensive evaluation scripts:
- Federated Learning Performance
- Computation Overhead
- Communication Overhead
- Storage Overhead: run `stoOver_2.py` and `stoOver_TA.py` to test storage cost in the vehicle and TA for identity management
- Blockchain Access Time: run `Access.java` to test on chain access time

## ⚙️Requirements
- circom >= v2.0
- node.js >= 14
- snarkjs
- Python >= 3.7
- Common libraries: numpy, pandas, scikit-learn, matplotlib... (for FL)
