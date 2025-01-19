# EUROPE COMMISSION RECOMMENDATION

#### Key Concepts and Terminology
Post-Quantum Cryptography (PQC) represents a critical evolution in securing digital infrastructures against the emerging threat of quantum computing. With the advent of quantum computers, current cryptographic standards, particularly asymmetric cryptography, face the risk of being rendered obsolete due to their vulnerabilities to quantum attacks. The European Commission's "Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography" establishes a foundational framework for transitioning to PQC.

#### Context and Importance
The European Commission emphasizes the strategic importance of encryption in safeguarding the digital ecosystem. This includes ensuring the confidentiality and integrity of sensitive communications, securing public administration systems, and maintaining critical infrastructure resilience. Quantum computing introduces a dual-edged potential—while unlocking groundbreaking opportunities, it simultaneously threatens traditional cryptographic mechanisms.

#### Objectives Outlined in the EU Recommendation
The document delineates clear objectives to guide member states through a coordinated and harmonized transition:
1. **Defining a Coordinated Roadmap**: Establishing a joint implementation strategy across the European Union.
2. **Standardizing Algorithms**: Selecting and adopting PQC algorithms as Union-wide standards.
3. **Supporting National Transition Plans**: Encouraging member states to align national plans with the EU's coordinated roadmap.
4. **Stakeholder Engagement**: Involving a broad spectrum of actors, including cybersecurity experts, industry participants, and government agencies.

#### Vulnerabilities in Cryptographic Systems
Quantum computing poses specific risks to:
- **Asymmetric cryptography**: Algorithms like RSA, ECC, and DH are highly susceptible to quantum attacks.
- **Public Key Infrastructure (PKI)**: The foundational mechanisms ensuring trust in digital certificates face significant challenges.
- **Long-Term Confidentiality**: Sensitive data stored today could be decrypted retrospectively with future quantum advancements.

#### Implementation Strategy
The document proposes a structured approach:
- **Hybrid Cryptographic Models**: Gradual integration of PQC with existing cryptographic systems to ensure compatibility during the transition phase.
- **Interoperability Focus**: Collaboration at the EU level to establish standards ensuring seamless communication across borders.
- **Monitoring and Review**: Continuous assessment of progress and effectiveness, with provisions for additional legislative actions if required.

#### Compliance and Governance
The roadmap aligns with broader EU cybersecurity strategies and respects fundamental rights under the EU Charter of Fundamental Rights and the European Convention on Human Rights. It mandates the inclusion of representatives from relevant national security and cybersecurity agencies, fostering an inclusive governance model.

### Modular Integration
This section forms the foundational layer of understanding PQC transition. Subsequent parts will expand on open-source tools, cryptographic inventories, and agility mechanisms while tying back to the principles and strategies outlined here.

# QUANTUM-READINESS: MIGRATION TO POST-QUANTUM CRYPTOGRAPHY
#### Building Quantum-Readiness for Migration to PQC

The "Quantum-Readiness: Migration to Post-Quantum Cryptography" framework developed by the CISA, NSA, and NIST provides practical guidance for organizations—especially those managing critical infrastructure—on preparing for the shift to Post-Quantum Cryptography (PQC). It emphasizes proactive measures to mitigate the risk posed by cryptanalytically relevant quantum computers (CRQC).

---

### Key Concepts and Urgency of Preparation

#### The Threat of CRQC
Cryptanalytically relevant quantum computers have the potential to break widely used public-key cryptographic systems such as RSA, ECC, and ECDSA. Organizations need to anticipate this future threat, especially for systems safeguarding sensitive data with long-term confidentiality requirements.

#### Why Prepare Now?
Early preparation minimizes risks associated with the "harvest now, decrypt later" strategy by adversaries who collect encrypted data now for future decryption. Organizations must transition to PQC before such quantum threats become operational realities.

---

### Establishing a Quantum-Readiness Roadmap

Organizations are advised to build a roadmap by:
1. **Forming a Project Management Team**: Tasked with identifying and prioritizing quantum-vulnerable systems and overseeing migration efforts.
2. **Conducting Cryptographic Discovery**: Mapping current dependencies on quantum-vulnerable algorithms like RSA and ECC.
3. **Collaborating with Vendors**: Understanding vendors' quantum-readiness roadmaps and influencing their timelines for PQC integration.

---

### Preparing a Cryptographic Inventory

A comprehensive cryptographic inventory is central to quantum-readiness:
- **Purpose**:
  - Identifies systems at risk due to quantum-vulnerable cryptography.
  - Guides prioritization in transitioning to PQC.
  - Supports a transition to zero-trust architectures.

- **Steps**:
  1. **Discovery Tools**: Utilize tools to identify cryptographic algorithms in:
     - Network protocols.
     - End-user applications and firmware.
     - Continuous delivery pipelines.
  2. **Vendor Engagement**: Request detailed lists of embedded cryptographic technologies from vendors.
  3. **Integration with Risk Assessments**: Feed inventory data into broader organizational risk assessments to prioritize critical transitions.

- **Special Focus**:
  - Correlate the cryptographic inventory with asset inventories and access management systems.
  - Identify dependencies involving high-risk or long-term confidentiality data.

---

### Engagement with Technology Vendors

#### Vendor Responsibilities
- Vendors must align their development roadmaps with emerging PQC standards.
- Testing and integration of quantum-resistant algorithms into products are crucial to the Secure by Design principle.

#### Key Actions for Organizations
- Actively engage with vendors on:
  - Transition timelines for both legacy and modern products.
  - Costs and implications of migration to PQC.
- Collaborate with cloud service providers to plan for PQC integration, ensuring compatibility and effective implementation.

---

### Addressing Supply Chain Dependencies

Organizations should assess quantum-vulnerable cryptographic dependencies across their supply chain, prioritizing:
- **Critical Systems**: Industrial control systems (ICS) and long-term secrecy needs.
- **Custom Technologies**: Custom-built solutions require bespoke upgrades to migrate to PQC.
- **Cloud Services**: Partner with providers to enable PQC configurations post-standards release.

---

# Post-Quantum Cryptography (PQC) Migration Handbook

---

### Chapter 1: Introduction

The **Post-Quantum Cryptography (PQC) Migration Handbook** serves as a practical guide for organizations to address the impending risks posed by quantum computers to current cryptographic systems. While numerous papers highlight the urgency and risks associated with quantum computing, this handbook provides actionable steps to develop a migration strategy, targeting organizations that need immediate preparedness, referred to as *urgent adopters*. 

#### **Key Concepts and Goals**
1. **Cryptography and Its Importance**: 
   - Cryptography underpins cybersecurity, safeguarding sensitive data, ensuring data integrity, and preventing unauthorized access.
   - Weak cryptography exposes organizations to risks such as data breaches, theft, and unauthorized access to sensitive systems.

2. **Threat of Quantum Computers**:
   - Classical cryptography, secure against traditional computing attacks, will become vulnerable with the advancement of quantum computers.
   - Within 10–20 years, quantum computers could render many current cryptographic algorithms obsolete.

3. **Post-Quantum Cryptography (PQC)**:
   - PQC schemes are resistant to quantum computing attacks, necessitating their adoption as the future standard.
   - Migration to PQC involves substantial resources (time, budget, manpower) and technical adaptations, especially for legacy systems.

#### **Urgency of Migration**
Three key risks justify early action:
1. **Store-Now-Decrypt-Later Attacks**:
   - Sensitive information intercepted today can be decrypted in the future using quantum computing.
   - Long-term sensitive data is already at risk.

2. **Long-Lived Systems**:
   - Systems developed today may not support future PQC updates, posing risks for critical infrastructure.

3. **Complexity of Migration**:
   - Historical migrations, like from SHA-1 to SHA-256, demonstrate that transitioning cryptographic systems is time-consuming and resource-intensive, requiring years of preparation.

#### **Handbook Objectives**
This document assists organizations in:
- Assessing risks posed by quantum computing to their cryptographic landscape.
- Outlining the steps needed for a successful migration to PQC.
- Addressing technical and strategic considerations for migration.

#### **Associated Risks of Quantum Threats**
- **Timing Uncertainty**: While quantum computers are not yet capable of breaking classical cryptography, breakthroughs may hasten their arrival.
- **Asset Lifespan**:
  - Assets requiring long-term confidentiality (e.g., sensitive data) are already vulnerable to quantum decryption attacks.
  - Other functionalities like authentication face threats only when quantum systems become operational.
- **Premature Migration Risks**: Migrating too early may result in repeated efforts if vulnerabilities are discovered in new PQC algorithms.
- **Delayed Migration Risks**: Late migration could lead to severe consequences, including data breaches and reputational damage.

#### **Document Structure**
The handbook follows a **three-step approach** for PQC migration:
1. **Diagnosis**:
   - Identify urgency and assess cryptographic dependencies within the organization using PQC personas and decision trees.
2. **Planning**:
   - Formulate technical and organizational migration strategies, prioritizing assets based on risk and urgency.
3. **Execution**:
   - Implement migration strategies with detailed technical guidance.

The subsequent chapters provide:
- **Chapter 2**: PQC diagnosis, urgency assessment, and inventory creation.
- **Chapter 3**: Migration planning at technical and organizational levels.
- **Chapter 4**: Technical strategies for migrating cryptographic algorithms.
- **Chapter 5**: Technical references for cryptographic schemes.

#### **Quantum Key Distribution (QKD) vs. PQC**
While QKD offers quantum-resistant key exchange, its practicality is limited due to:
- High infrastructure costs and reliance on physical communication channels.
- Security vulnerabilities in QKD devices.
- Inability to replace classical cryptography entirely.

PQC is considered the superior and more practical solution for quantum threats, endorsed by major security agencies.

#### **Key Recommendations**
- Early diagnosis of cryptographic assets and vulnerabilities to determine migration urgency.
- Preparation for PQC adoption by prioritizing assets, establishing migration plans, and allocating resources.
- Collaboration with vendors and stakeholders to ensure cryptographic agility and compatibility with PQC standards.

---

### Chapter 2: Diagnosis

This chapter outlines the foundational steps for determining an organization’s need to migrate to Post-Quantum Cryptography (PQC). It provides tools and frameworks for assessing the urgency of migration and conducting a comprehensive diagnosis of an organization’s cryptographic landscape.

---

#### **2.1 PQC Personas**

To streamline PQC adoption, organizations are categorized into *PQC Personas*, reflecting their migration urgency based on assets, risks, and dependencies:

1. **Urgent Adopters**:
   - Handle sensitive or long-lived data or critical infrastructure.
   - Immediate action is required to safeguard against quantum threats like *store-now-decrypt-later* attacks.
   - Subcategories include:
     - **Personal Data Handlers**: Focus on long-term protection of individual data (e.g., healthcare, finance).
     - **Organizationally Sensitive Data Handlers**: Secure organizational data like trade secrets or state information (e.g., governments, military).
     - **Critical Infrastructure Providers**: Maintain essential services (e.g., energy, water, telecoms).
     - **Long-Lived Infrastructure Providers**: Develop systems with a lifespan beyond 20 years requiring future-proofing (e.g., satellites, payment systems).

2. **Regular Adopters**:
   - Do not face immediate quantum risks but should monitor developments and maintain crypto-agility.
   - Often includes retailers, schools, and smaller organizations with lower data sensitivity.

3. **Cryptography Experts**:
   - Develop and supply cryptographic tools and solutions.
   - Must prepare quantum-safe products and communicate readiness to clients.

#### **Determining Your Persona**
Organizations should evaluate:
- Their cryptographic infrastructure, knowledge, and dependency on others.
- Supply-chain risks and inherited personas from suppliers or clients.

**Recommendation**: Organizations on the boundary between urgent and regular adopters should err on the side of caution and consider initiating the diagnostic process early.

---

#### **2.2 PQC Diagnosis**

For organizations identified as **Urgent Adopters**, the PQC diagnosis is the first step in migration. It focuses on gathering information to assess risks, prioritize assets, and plan mitigation strategies. The diagnosis involves the following key steps:

1. **Risk Assessment**:
   - Reassess risks with the quantum threat in mind.
   - Identify new vulnerabilities in cryptographic algorithms and anticipate quantum-related attacks.

2. **Inventory of Cryptographic Assets**:
   - Compile a detailed list of all cryptographic assets, including:
     - Algorithms, key lengths, and usage.
     - Dependencies on external suppliers.
   - Utilize tools like Configuration Management Databases (CMDBs) and automated discovery tools.

3. **Inventory of Data Assets**:
   - Categorize and assess data based on:
     - Type (e.g., at rest, in transit).
     - Location, value, and sensitivity.
     - Classification and risk assessment.

4. **Inventory of Cryptographic Dependencies**:
   - Identify suppliers of cryptographic assets and ensure their readiness for PQC.
   - Establish communication with vendors to understand their migration plans.
   - Consider supply-chain risks, including dependencies on third-party cryptographic infrastructure.

---

#### **Key Considerations**

1. **Interoperability**:
   - Organizations within interconnected ecosystems should coordinate migration efforts to maintain security and operational compatibility.

2. **Multiple Personas**:
   - Some organizations may identify with multiple personas (e.g., financial institutions as both Personal and Organizational Data Handlers). Action steps should prioritize assets based on specific risks.

3. **Regular Adopters**:
   - While immediate migration is unnecessary, regular adopters should:
     - Maintain crypto-agility.
     - Stay informed on PQC standards and timelines.
     - Begin preparatory steps such as risk assessment and asset inventory.

4. **Cryptography Experts**:
   - Experts should actively transition products to PQC and support client readiness.
   - Communicate timelines and quantum-safety measures to ensure downstream compliance.

---

#### **Running the PQC Diagnosis**

The diagnosis phase is a critical precursor to migration. It provides insights into:
- Which assets to prioritize for quantum-safe upgrades.
- Dependencies on vendors and their readiness.
- Data and infrastructure vulnerabilities requiring urgent mitigation.

**Outcome**: The results of the diagnosis guide the development of a strategic and technical migration plan in subsequent phases.

---

### Chapter 3: Migration Planning

This chapter provides detailed guidance for planning the transition to Post-Quantum Cryptography (PQC). It focuses on when and how organizations, particularly urgent adopters, should initiate the migration process, ensuring a structured and efficient approach.

---

#### **3.1 When to Start Migrating?**

##### **3.1.1 Migration Scenarios**

The timeline for migration depends on three critical factors:
- **X**: The time the asset must remain secure.
- **Y**: The time required for migration.
- **Z**: The estimated time until quantum computers can break current cryptographic systems.

Migration should satisfy **Mosca’s inequality: X + Y < Z**. If **X > Z**, immediate migration is essential.

##### **Four Migration Scenarios**
Based on milestones in PQC development, organizations can choose from:
1. **Scenario 1**: Immediate migration using uncertified libraries.
2. **Scenario 2a/2b/2c**: Migration during the availability of production-level or community-tested PQC libraries.
3. **Scenario 3**: Migration after certified libraries and standards are established.

**Key Considerations**:
- Earlier migration (Scenario 1 or 2) involves risks like using uncertified libraries, but may be necessary for high-risk assets.
- Later migration (Scenario 3) ensures stability but risks exposure to quantum threats during the waiting period.
- Organizations must balance their risk tolerance, asset criticality, and timeline estimates.

##### **Estimating Timelines**
- **Wi (Waiting Time)**: Based on milestones for production-ready or certified PQC solutions. Organizations can influence these timelines through vendor engagement.
- **Yi (Migration Time)**: Varies by asset and complexity of implementation.
- **Z (Quantum Breakthrough Timeline)**: Expert consensus suggests 2030–2040 as potential milestones for quantum computers breaking RSA-2048.

##### **Step-by-Step Process**
1. **Estimate Timelines**: Use available data and expert opinions to approximate Wi, Yi, and Z.
2. **Determine Migration Scenario**: Use a decision tree to align assets with the most appropriate scenario.
3. **Develop a General Strategy**:
   - Begin with modernizing cryptographic systems.
   - Transition to PQC incrementally, starting with the most critical assets.

---

#### **3.2 Advice on Migration Planning**

##### **3.2.1 Business Process Planning**
Migration involves significant business considerations:
- **Migration Manager**: Appoint a leader with organization-wide access to oversee the transition.
- **Budget Allocation**: Plan for costs related to personnel, infrastructure, and potential system replacements.
- **Downtime Management**: Anticipate and minimize service interruptions by coordinating with stakeholders and similar organizations.

##### **Costs**
Migration is resource-intensive, requiring:
- Dedicated teams to inventory and prioritize cryptographic assets.
- Potential hardware upgrades to support PQC algorithms, which often require more computational resources.
- Contingency planning for vendor delays or insufficient PQC support.

##### **Interoperability**
- Coordinate with partners and stakeholders to maintain compatibility during the migration.
- Collaborative planning can reduce workloads and ensure smooth transitions.

---

#### **3.2.2 Technical Planning**

##### **Dependency of Assets**
- Identify interdependencies between cryptographic assets.
- Maintain interoperability by temporarily supporting dual systems (classical and quantum-safe protocols).

##### **Cryptography Replacement**
- Decide whether to replace, redesign, or retire each cryptographic asset.
- Select quantum-safe solutions that are crypto-agile, ensuring flexibility for future updates.

##### **Asset Isolation**
For particularly sensitive assets:
- Use isolation to protect against attacks during migration.
- Employ physical or logical separation, though this may disrupt functionality.

##### **Hardware Replacement**
- Assess the capability of existing hardware to support PQC.
- Plan for deployment timelines if hardware upgrades are necessary.

##### **Testing**
- Thoroughly test new algorithms and hardware to ensure compatibility and security.
- Incorporate testing into the migration timeline to prevent post-migration vulnerabilities.

---

#### **Key Takeaways**
- **Timely Migration**: Organizations must evaluate the urgency of migration based on the criticality of their assets and their estimated timelines for quantum threats.
- **Structured Planning**: Prioritize high-risk assets, allocate sufficient resources, and coordinate with stakeholders to ensure smooth transitions.
- **Flexibility**: Opt for crypto-agile solutions to accommodate evolving PQC standards and mitigate future risks.

---

### Chapter 4: Execution Summary

Chapter 4 provides a comprehensive guide for executing the migration to post-quantum cryptography (PQC). This process involves general strategies, detailed steps for migrating cryptographic primitives and protocols, and an emphasis on ensuring cryptographic agility. Key highlights include:

---

#### **4.1 General Strategies**
- **Long Process Awareness**: Migration is a multi-year endeavor. Start with planning and updating cryptographic inventories.
- **Dynamic IT Environments**: Continuously update asset inventories to reflect current cryptographic use.
- **Careful Implementation**: Missteps in cryptographic replacement can introduce vulnerabilities. Hybrid schemes combining classical and PQC algorithms are recommended for early stages.

---

#### **4.2 Cryptographic Agility**
Cryptographic agility enables quick adaptation to new cryptographic standards without major architectural changes. Steps include:
1. Abstract cryptographic operations using high-level libraries or external key management solutions.
2. Conduct cryptographic agility scans as part of CI/CD pipelines.
3. Evaluate hardware readiness for PQC's computational demands.

---

#### **4.3 Migration of Primitives vs. Protocols**
- **Primitives**: Low-level algorithms (e.g., RSA, AES) form the foundation of cryptographic protocols.
- **Protocols**: Systems like TLS, SSH, and IPSec that integrate primitives.

---

#### Migration of Primitives
1. **Symmetric Cryptography and Hash Functions**:
   - Increase key lengths and hash outputs to mitigate quantum threats (e.g., AES-256, SHA-3-256).
   - Update long-lived systems that cannot be modified later.
2. **Asymmetric Cryptography**:
   - **Hybrid Solutions**: Use classical and PQC algorithms in tandem to ensure security during transition.
   - Avoid "hybrid OR" setups prone to downgrade attacks.
   - Consider pre-shared keys for environments with strict trust and control, but acknowledge scalability limits.

---

#### Migration of Protocols
Protocols require adaptation to ensure quantum safety:
1. **TLS**:
   - Options: Pre-shared keys or hybrid key exchange.
   - Configure cipher suites for quantum-safe encryption (e.g., AES-256-GCM).
2. **SSH**:
   - Employ hybrid key exchange for secure remote access.
3. **S/MIME**:
   - Limited research; hybrid approaches or avoiding sensitive email exchanges are recommended.
4. **PGP**:
   - Await further research and developments for quantum-safe alternatives.
5. **IPSec**:
   - Use pre-shared keys or hybrid solutions for secure VPN communication.
6. **X.509 Certificates**:
   - Transition to hybrid certificates for authenticating public keys.

---

#### Challenges and Recommendations
- **Downgrade Attacks**: Hybrid OR configurations may allow attackers to bypass post-quantum algorithms.
- **Pre-shared Keys**: High-security but impractical for large-scale systems due to logistical challenges.

---

#### Table of Recommended, Acceptable, and Prohibited Cryptographic Primitives
The handbook provides a detailed table for cryptographic primitives categorized by functionality (e.g., block ciphers, stream ciphers, digital signatures). Highlights include:
- **Recommended**: AES-256, CRYSTALS-KYBER (PQC public-key encryption).
- **Acceptable**: Camellia-256, FrodoKEM (conservative PQC alternatives).
- **Do Not Use**: RSA, DSA, and MD5, as they lack quantum resistance.

---

### Chapter 5: Background on Primitives

#### **Purpose of the Chapter**
This chapter provides guidance for library developers and organizations on selecting cryptographic primitives for quantum-safe protocols. It also aids in:
- **Asset discovery**: Identifying cryptographic assets in use.
- **Risk assessment**: Evaluating the vulnerabilities of these assets.
The chapter assumes familiarity with the cryptographic landscape and provides a categorized list of commonly used primitives, their characteristics, and their quantum security status.

---

#### **5.1 Classical Primitives**

Classical primitives are categorized into:
1. **Symmetric Ciphers**
2. **Asymmetric Ciphers**
3. **Hash Functions**
4. **Message Authentication Codes (MACs)**
5. **Stateful Hash-Based Signatures (HBS)**

##### **5.1.1 Symmetric Ciphers**
- **AES**: Widely used block cipher supporting 128, 192, and 256-bit keys. It is quantum-secure with 256-bit keys.
- **(T)DES**: Deprecated due to its short key lengths. Insecure against both classical and quantum attacks.
- **ChaCha20**: Stream cipher known for speed and simplicity. Quantum-secure with 256-bit keys.
- **Blowfish**: Legacy cipher with small block sizes, making it vulnerable to birthday attacks.
- **RC4**: Insecure in classical settings and not recommended.
- **Camellia**: Secure alternative to AES with similar features. Quantum-secure with 256-bit keys.

##### **5.1.2 Asymmetric Ciphers**
- **RSA**: Based on integer factorization. Insecure against quantum attacks.
- **ElGamal**: Relies on the Diffie-Hellman problem. Quantum-unsafe.
- **ECDSA/ECDH**: Elliptic curve variants for digital signatures and key exchange. Both are quantum-unsafe.
- **EdDSA**: Modern digital signature scheme, but quantum-unsafe.

##### **5.1.3 Hash Functions**
- **SHA Family**: Includes SHA-2 and SHA-3, quantum-secure if 256-bit or higher output sizes are used.
- **MD5**: Deprecated due to vulnerabilities. Insecure even in classical settings.
- **BLAKE2**: Faster alternative to SHA-3. Quantum-secure with 256-bit or higher outputs.

##### **5.1.4 Message Authentication Codes (MACs)**
- **HMAC**: Constructed using cryptographic hashes. Quantum-secure if underlying hash is quantum-safe.
- **BLAKE2-MAC**: Faster than HMAC due to integrated keying. Quantum-secure with BLAKE2b.
- **CBC-MAC and CMAC**: Derived from block ciphers, both quantum-secure with 128-bit or higher quantum-safe hashes.
- **Poly1305**: High-speed MAC paired with ChaCha20. Quantum-secure.

##### **5.1.5 Stateful Hash-Based Signatures (HBS)**
- **XMSS and XMSSMT**: Based on Merkle hash trees, suitable for one-time and limited-use signatures. Quantum-secure but require state management.
- **LMS and HSS**: Variants of stateful hash-based signatures. Quantum-secure with proper implementation.

---

#### **5.3 Post-Quantum Primitives**

Post-quantum primitives address vulnerabilities in classical cryptography caused by quantum computing. They are classified into:
1. **Digital Signature Schemes (DSS)**
2. **Key Exchange Mechanisms (KEMs)**

##### **5.3.1 Digital Signature Schemes**
- **CRYSTALS-Dilithium**: Lattice-based with high confidence and security levels. Suitable for general use.
- **FALCON**: Lattice-based, efficient but requires floating-point operations.
- **SPHINCS+**: Stateless hash-based signature with reduced sizes. High confidence and security.

##### **5.3.2 Key Exchange Mechanisms**
- **BIKE**: Code-based KEM with high security but large key sizes. Still under evaluation.
- **Classic McEliece**: Code-based KEM with very large public keys but small ciphertexts. Suitable for specific use cases.
- **CRYSTALS-Kyber**: Lattice-based KEM with moderate key and ciphertext sizes. High confidence and efficiency.
- **FrodoKEM**: Lattice-based KEM known for conservative security but large key sizes. Not selected for NIST standardization.
- **HQC**: Code-based KEM focusing on strong theoretical foundations and moderate key sizes.

---

#### **Recommendations for PQC Migration**
1. **Cryptographic Inventory**:
   - Identify all cryptographic primitives in use.
   - Evaluate their quantum security status.

2. **Selection of Primitives**:
   - Transition to quantum-safe primitives, prioritizing those with high confidence and standardization (e.g., CRYSTALS-Dilithium and Kyber).
   - Replace deprecated algorithms like MD5, RC4, and (T)DES.

3. **Performance and Scalability**:
   - Balance security with operational efficiency.
   - Consider resource-intensive primitives carefully (e.g., McEliece's large keys).

4. **Implementation Considerations**:
   - Ensure proper state management for stateful signatures.
   - Opt for stateless signatures (e.g., SPHINCS+) where possible.
