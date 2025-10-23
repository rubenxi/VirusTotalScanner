# VirusTotalScanner

Bash script to send all the files in a folder to VirusTotal for analysis.

Some antivirus solutions for Linux are either too complex or inaccurate, especially for file formats that are not native to the OS. To address this, I created this simple script that scans an entire folder and identifies all files of a given format (e.g., `.exe` and `.dll`). These file types are among the most dangerous on a Linux system that uses Wine or handles Windows files.

![File Format](https://github.com/user-attachments/assets/d2758fb9-7322-4eba-a351-d807cbced67f)

There are two categories of malware detections:
- **Malicious**: Likely false positives. Malware was detected by only a small number of antivirus engines.
- **Really Malicious**: Detected by a large number of antivirus engines. Most likely genuine malware.

![VirusTotal Reports](https://github.com/user-attachments/assets/5446d60a-28ab-4666-93a5-32362fd8e825)

By default, the script will query VirusTotal to check if the file is in their hash database and retrieve the analysis results. If the file is not found, it will be uploaded for a new analysis.

![Skip Upload](https://github.com/user-attachments/assets/b4cbb304-9c63-4777-9365-968cc509340e)

This behavior can be disabled using the flag `--skip-upload`.

![Skip Flag](https://github.com/user-attachments/assets/d9a991c3-bd31-49e6-92a9-7fb1b5f484cb)

The script accepts an array of API keys, which the user can input into the `api_keys` variable. It then iterates over the keys to scan each file.

This script is designed with simplicity in mind and uses as few libraries as possible, so no additional installations are required for most Linux systems.

A new file is created in the `/tmp/` folder containing the details of the analysis made in the last run of the script.

## Usage

```bash
./VirusTotalScanner.sh [flags]
````

## Allowed Flags

* `--skip-upload`: Skip the file if the hash is not present in the VirusTotal database.

## Requirements

* [VirusTotal API Key](https://www.virustotal.com/gui/my-apikey)
* `zenity`
* `curl`

