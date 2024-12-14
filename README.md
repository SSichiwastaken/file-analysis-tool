# File Analysis Tool
A Python-based CLI tool for file and hash analysis with VirusTotal and MalwareBazaar integration.  


# Features
- Calculate file hashes (SHA256).  
- Query VirusTotal and MalwareBazaar for file information.  
- Upload unknown files to VirusTotal for analysis.  
- Persistent API key management for VirusTotal.  


# Installation
- Clone Repository
```bash
git clone https://github.com/SSichiwastaken/file-analysis-tool.git
```

- Navigate to Installed Folder
```bash
cd file-analysis-tool
```

- Install Dependencies
```bash
pip install -r requirements.txt
```

# Usage
```bash
python3 file_analysis_tool.py -f {FILE} -k {YOUR_VIRUSTOTAL_API_KEY} --tools {virustotal malwarebazaar}
```


# Example
![2024-12-14 21_17_08-Settings](https://github.com/user-attachments/assets/f5dc53bc-d003-4c6e-b2a3-64f924125dfc)
