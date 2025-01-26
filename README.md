# Crypto Scanner

This project involves developing a Cryptographic Inventory Tool (Crypto Scanner) capable of detecting, prioritizing, and managing vulnerabilities in cryptographic primitives and protocols.

Building on concepts introduced in Part 1, the project emphasizes cryptographic agility and post-quantum cryptography (PQC) readiness. Using Python as the target programming language, the tool combines pattern-based analysis and semantic inspection to ensure comprehensive detection of vulnerabilities.

![alt text](https://github.com/epap011/Transition-Framework-for-PQC/blob/main/assets/images/crypto_scanner_app.png?raw=true)

## Installation

### Using Python (Local Installation)

1. Clone the repository:
```bash
git clone https://github.com/your-username/cryptographic-inventory-tool.git
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
cd app/src
python main.py
```

### Using Docker
1. Build the Docker image:
```bash
docker build -t crypto-scanner .
```

2. Run the Docker container:
```bash
docker run crypto-scanner
```

## Contributions
This tool was implemented by **Nick Giovanopoulos** and **Efthimis Papageorgiou** for the purposes of the course CS458 - Introduction to Cryptography. Feel free to open issues or submit pull requests to improve the tool.