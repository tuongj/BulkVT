# BulkVT
A GUI-based tool to retrieve preexisting scans of hashes from VirusTotal. BulkVT accepts single or hashes in large batches.

The tool features three selections to choose from: single, bulk, and directory.
- Single - Allows one to enter a hash or select a file to receive VirusTotal results. Selected files are hashed prior to submitting them to VirusTotal
- Bulk - Takes in large batches of hashes and submits them to VirusTotal. Accepts formats in CSV, TXT, or LOG.
- Directory - Recursively hashes files in a directory and subdirectories prior to submitting them to VirusTotal

# Prerequisite
- A Public API v2.0 key from VirusTotal. Register at https://www.virustotal.com to receive an API key for free.
