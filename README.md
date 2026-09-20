# FORENSIC SHIELD

**Military-grade privacy.** Designed for impenetrability and maximum resistance against the most advanced cyber-forensics laboratories.

## Philosophy, Purpose & Threat Model

The **FORENSIC SHIELD** application was originally developed solely for personal use, but is now being released to the public on the occasion of the **250th anniversary of the independence of the United States of America**.

We believe that in today's highly monitored world, where certain countries such as China, Russia, and Iran are constantly attempting to control their own citizens and people elsewhere in the world by violating individual privacy, suppressing freedoms, and compromising sensitive information, privacy-protection tools play a vital role.

This application is intended as a direct defensive tool against this type of state surveillance. The software is designed for free individuals and supporters of democracy.

## Why FORENSIC SHIELD? — Final Defense Approach

Most well-known encryption tools available on the market either lack genuine security layers against advanced cyberattacks, have insufficiently transparent backgrounds and resources, or rely on outdated protocols.

The **FORENSIC SHIELD** application has been engineered with one specific objective: **maximum resistance of encrypted output files against cyber-forensics laboratories (Cyber Labs Resistance).**

This means that even if your encrypted files fall into the hands of highly skilled government hackers and advanced cyber-forensics laboratories, the encrypted data is designed to provide the highest possible level of mathematical and technical resistance.

## Technical & Defensive Specifications

**Advanced Cryptographic Engine:**
We use **three engines with three different security/performance levels**. Each engine is designed with a different balance between encryption speed and maximum cryptographic strength.

### Encryption Algorithm

A combination of **AES-256-GCM** and **XChaCha20-Poly1305** is used to create a layered defensive shield.

### KDF

* **Modern Key Derivation:** Uses the **Argon2id** algorithm to provide strong resistance against hardware-based attacks and brute-force attacks.

### Double Encryption

Our **Double Password** capability allows each file to be encrypted **twice using two different passwords**.

### Text Encryption

Text encryption is also supported through two different security levels.

The first engine uses **XChaCha20 with Argon2id**, with maximum compression and a specific focus on keeping the encrypted output as short as possible.

The second engine uses **two-layer encryption based on AES-256 and XChaCha20**, combined with **Argon2id**, together with techniques designed to conceal the size and length characteristics of the original input text.

### Secure Deletion

Secure deletion of files is designed to make them **unrecoverable**.

Mobile flash storage has inherent technical limitations and does not behave like traditional magnetic storage. Without requiring root access, and while taking these limitations into account, the application attempts to securely delete files as effectively as possible.

### Metadata Removal

Complete removal of metadata from photos and files, including **EXIF data, GPS coordinates, creation timestamps, and device information**, before sensitive files are shared.

The objective is to maximize privacy and neutralize digital traces associated with sensitive content.

### RAM Sanitization

Immediate clearing and destruction of passwords, cryptographic keys, and other sensitive structures from **RAM**, with the goal of reducing the possibility of key-material leakage if the device is seized or confiscated.

### 100% Offline Architecture (Zero-Knowledge)

* No backdoor
* No Internet connection required
* No Internet permission
* No cloud dependency

The application is designed to operate entirely offline.

## Documentation & Quick Links

* **User Guide:** For step-by-step instructions covering different encryption modes, options, and features, see the [USAGE.md](https://chatgpt.com/c/USAGE.md) file.
* **Legal Terms:** For the complete legal framework, terms, and conditions governing use and compliance, see the [LICENSE.txt](https://chatgpt.com/c/LICENSE.txt) file.

## License & Terms of Use — Source-Available License

This software is released as a **Source-Available** project.

Access to the source code is provided solely for the purposes of transparency, demonstrating the absence of a backdoor, and enabling security auditing by users.

Any copying, modification, reverse engineering, visual modification (**re-skinning**), or redistribution of the software without the developer's explicit written permission is strictly prohibited by law and may be subject to legal action.

All legal terms and conditions are set forth in the [LICENSE.txt] file.

**Disclaimer:** This software is provided **"AS IS"**. The developer assumes no responsibility or liability for any consequences resulting from the use, misuse, or operation of this software. **100% of all legal responsibility rests entirely with the user.**

## Contact & Security Reports

For questions, security audit reports, official correspondence, collaboration requests, or any other matters, you may contact the developer through the following email address:

Email: liberty88intell@gmail.com
