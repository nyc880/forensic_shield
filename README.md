
# Liberty Shield

Military-grade true privacy. Designed for impenetrability and maximum resistance against the most advanced Cyber Forensic Labs.

## Philosophy, Purpose & Threat Model
The Liberty Shield application was initially built solely for personal use, but it is now being released to the public on the occasion of the 250th anniversary of the United States of America's Independence.

We believe that in today's monitored world, where certain countries like China, Russia, and Iran are constantly attempting to control their citizens and the rest of the world by breaching individual privacy, suppressing freedoms, and hacking information, privacy protection tools play a vital role. This program is a direct defensive tool against this type of state surveillance. This is software for free individuals and supporters of democracy.

## Why Liberty Shield? (The Ultimate Alternative)
Most famous encryption tools available on the market either lack true security layers against cyber attacks, have unclear government backgrounds, or use outdated protocols.

The Liberty Shield application has been engineered with a specific objective: maximum resistance against cyber laboratories (Cyber Labs Resistance). This means that if your encrypted files or your device fall into the hands of the most expert government hackers and cyber forensic labs, it will demonstrate the highest mathematical and technical resistance.

Look at the image below to see the difference in technical approach and security target between Liberty Shield and other common tools:


| App Name       | Cipher Engine        |          KDF   |safeWipe| RAM Zeroization| Double Encryp|Security Target|
|----------------|----------------------|----------------|--------|----------------|--------------|---------------|
|*Liberty shield*| AES-256-GCM+ChaCha20 | Argon2id + HKDF| Yes    | Yes            | Yes          | State/Military|
|*Cryptomator*   | AES-256              | scrypt         | No     | Weak           | No           | Cloud-Centric |
|*AxCrypt*       | AES-256              | PBKDF2         | No     | Weak           | No           | Commercial    |
|*EDS*           | AES-256 / Serpent    | PBKDF2         | No     | Medium         | Yes          | Advanced      |
|*SSE*           | AES-256 / Serpent    | Argon2id + HKDF| No     | Medium         | Yes          | High-Level    |
|*ZArchiver*     | AES-256              | PBKDF2         | No     | Weak           | No           | Basic         |
|*DroidFS*       | AES-256-GCM/XChaCha20| scrypt         | Limited| Medium         | No           | Open-Source   |
|*Folder Lock*   | AES-256              | PBKDF2 / Basic | No     | Weak           | No           | Consumer      |
|*Solid Explorer*| AES-256              | PBKDF2         | No     | Weak           | No           | Basic         |



## Technical & Defensive Specifications
* Advanced Cipher Engine: Concurrent combination of AES-256-GCM and ChaCha20 to create a two-layer defensive shield.
* Modern Key Derivation: Utilizing Argon2id + HKDF algorithms for the complete neutralization of hardware and brute-force attacks.
* Government-Level Secure Wipe: In compliance with strict NIST standards, rendering the recovery of deleted files impossible, even in forensic laboratories.
* **Zero-Trace Metadata Stripping:** Complete extraction and destruction of hidden file metadata (including EXIF data, GPS coordinates, creation timestamps, and device details) before sharing sensitive files, ensuring absolute privacy and neutralizing digital footprints.
* Instant Memory Cleansing (RAM Zeroization): Immediate purging and destruction of any passwords or sensitive structures from RAM to prevent key leakage in the event of device seizure.
* 100% Offline Architecture (Zero-Knowledge): No backdoors, no internet connection required (No Internet Permission), and zero cloud dependency.
* Secure Text Encryption: A dedicated, high-entropy module for sensitive notes, utilizing AES-256-GCM standards, secure clipboard management, and tamper-proof PDF export.

## Documentation & Quick Links
* **User Guide:** For step-by-step instructions on encryption modes (Just Files, Just Zip, Double Zip), advanced parameters, and safe RAM extraction, please refer to the [USAGE.md](USAGE.md) file.
* **Legal Terms:** For the complete legal framework and compliance rules, see the [LICENSE.txt](LICENSE.txt) file.

## License & Terms of Use (Source-Available License)
This software is released as a Source-Available project. Access to the source code is provided solely for transparency, proof of the absence of backdoors, and security auditing for users. Any copying, modification, reverse engineering, re-skinning, or redistribution without the explicit written permission of the developer is strictly prohibited by law and subject to legal prosecution. All legal terms are reserved in the [LICENSE.txt](LICENSE.txt) file.

*Disclaimer: This tool is provided "AS IS". The developer assumes zero liability for any consequences or alternative usages, and 100% of the legal responsibility rests entirely with the user.*



Contact & Security Reporting
For inquiries, security auditing reports, official correspondence, collaboration, or any other matter, please feel free to reach out to the developer via the email below: [liberty88intell@gmail.com]