# ADCSPotato

Automatically mine Certify AD CS output for non-standard low-priv principals and potential ESC1/2/3/4/7 paths, with JSON + Markdown reporting.

Built while working through Altered Security's CESP-ADCS, after realizing that Certify.exe's built-in attack path detection isn't as rich as Certipy, and Certipy can't easily highlight attack paths per-user unless you run it with that user's creds.

ADCSPotato parses Certify-style output plus a `Users.txt` list, finds "weird" users on CA/template ACLs, and reports possible ESC1/2/3/4/7 abuse paths in Markdown and JSON.

Huge thanks to Altered Security for the learning opportunity.

---

## Input files

ADCSPotato expects two simple text files in the working directory:

- `Users.txt`  
  - One **`samAccountName` per line**.  
  - Example:
    ```text
    j.doe
    a.nguyen
    svc_backup
    ```
  - These are usually low-priv or “interesting” users you want to check for AD CS abuse paths.

- `Output.txt`  
  - The raw output of **`Certify.exe find`** redirected to a file.  
  - Example:
    ```powershell
    Certify.exe find > Output.txt
    ```
  - ADCSPotato parses this file to map your `Users.txt` list to potential ESC1/2/3/4/7 paths.

---

## High-level workflow

1. Run `Certify.exe find` against the target environment and save the output to `Output.txt`.
2. Create `Users.txt` with one `samAccountName` per line for the users you care about.
3. Run `ADCSPotato.py` in the same directory.
4. Review the generated JSON / Markdown report for potential ESC1/2/3/4/7 attack paths.

<img width="1384" height="727" alt="Screenshot 2025-11-17 225410" src="https://github.com/user-attachments/assets/27ae09a7-87a9-4b4e-9f6e-c4e6bc31bf69" />
<img width="1023" height="849" alt="Screenshot 2025-11-17 225752" src="https://github.com/user-attachments/assets/49d5aec9-dbcc-41e4-a2a9-ff5f65ba80bb" />
