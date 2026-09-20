# Additional Information

## Main Screen

On the first screen, the **ENCRYPT** and **DECRYPT** buttons are used for file encryption and decryption.

You can then select files using the application's built-in file manager. Each file icon is divided into two clickable areas: clicking on one half opens the file for viewing, while clicking on the other half selects the file.

The **SYSTEM FILE MANAGER** button allows you to use your device's own system file manager instead.

---

# File Encryption

The **ENCRYPTION LEVEL** system provides three encryption engines:

### FAST

The **FAST** engine is designed with a focus on high encryption speed. The encryption process is performed as quickly as possible.

### MEDIUM

The **MEDIUM** engine provides an acceptable level of security while maintaining moderate encryption speed.

### MAX

The **MAX** engine focuses on maximum security. It performs **two-layer encryption using XChaCha20 and AES-256**.

The encryption process may take longer with this engine, but it is designed to provide an extremely high level of security.

### DOUBLE PASSWORD

The **DOUBLE PASSWORD** option performs the encryption process using two different passwords.

The files are first encrypted using your first password. The resulting encrypted files are then encrypted again using your second password.

### ZIP

The **ZIP** option places all of your selected files into a single ZIP archive, and then the ZIP file is encrypted.

### DELETE AFTER ENCRYPTION

The **DELETE AFTER ENCRYPTION** option sends the original file to the **SAFE DELETE** deletion engine after encryption has been completed, where it is securely deleted.

---

# File Storage Locations

Encrypted files are stored in a folder named **ENC** on your device.

Decrypted files are stored in a folder named **DEC**.

---

# Text Encryption

After entering the text encryption section, you will see two options at the top:

* **MEDIUM SHORT ENCRYPT**
* **MAXIMUM ENCRYPT**

## Medium Short Encrypt

The **MEDIUM SHORT ENCRYPT** engine is designed to provide fast encryption while keeping the encrypted output short, while maintaining a high level of security.

We use secure encryption algorithms and methods, together with compression techniques designed to keep the encrypted output controlled and relatively short while remaining secure.

In this section, both plaintext input and encrypted output are entered and displayed inside the **same text box**.

The **ENCRYPT** and **DECRYPT** buttons are used to perform the encryption and decryption operations.

The **SHARE** button allows you to send the encrypted text directly to **WhatsApp, Telegram, SMS**, or any other application or destination you choose.

You can also use the **SAVE** option to store the encrypted text.

Saved text files are stored inside a folder named **text ENC**, which is located inside the main **ENC** folder.

---

# Maximum Encrypt

The **MAXIMUM ENCRYPT** engine uses **two-layer encryption based on XChaCha20 and AES-256**, with a focus on the highest possible level of security.

The encryption process may take somewhat longer, but it is designed for maximum security.

Regardless of the original length of your text, additional noise is added to the encrypted data, transforming it into a much larger encrypted output.

This is designed to make it impossible to determine the original length of your sentence or text based on the encrypted output.

Because displaying such a long encrypted text directly in the application is not practical, the encrypted result is provided to you as a file.

To decrypt the text, you must import the generated file into the **DECRYPT** section of this same mode.

Alternatively, you can directly click on the generated file, and the application will automatically take you to the appropriate decryption section.

---

# Safe Delete

The **SAFE DELETE** section helps you securely delete your files with the goal of making them completely unrecoverable.

---

# Metadata Removal

This section removes all metadata from your file.

Please note that the new metadata-free file replaces the original file. The original file containing the metadata will no longer exist after the process is completed.

---

# Safe Exit

The **SAFE EXIT** button is designed to securely clean sensitive data from RAM before exiting the application.

This process is intended to ensure that generated passwords, cryptographic data, and other sensitive information held in RAM are securely cleared when the application closes.
