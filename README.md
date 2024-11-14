# VTScanner
 
This project is designed to scan files using their hashes, retrieve detailed results from VirusTotal, and generate a comprehensive report.

## Features

- **VirusTotal Integration**: Automatically privately scan via hashes and retrieves results from VirusTotal.
- **Detailed Reporting**: Merge scan results to output file

## Prerequisites

- Python 3.x
- VirusTotal API key

## Execution

   ```bash
   python main.py <Input Path> <column containing hash> <column to output the VT result>