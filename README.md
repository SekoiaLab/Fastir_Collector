# FastIR Collector
## Concepts

This tool collects different artefacts on live Windows and records the results in csv files. With the analyses of this artefacts, an early compromission can be detected.
## Requirements
- pywin32
- python WMI
- python psutil
- python yaml
- construct
- distorm3
- hexdump
- pytz

## Execution
- ./fastIR_x64.exe -h for help
- ./fastIR_x64.exe --packages fast  extract all artefacts without dump package artefacts
- ./fastIR_x64.exe --packages dump --dump mft to extract MFT
- ./fastIR_x64.exe --packages all --ouput_dir your_ouput_dir to set the directory output (by default is the current directory)
- ./fastIR_x64.exe --profile you_file_profile to set your own profile extraction

## Packages

Packages Lists and Artefact

  * fs
    * IE History
    * Named Pipes
    * Prefetch
    * Recycle-bin
    * health
    * ARP Table
    * Drives list
    * Network drives
    * Networks Cards
    * Processes
    * Routes Tables
    * Tasks
    * Scheluded jobs
    * Services
    * Sessions
    * Network Shares
    * Sockets

  * registry
    * Installer Folders
    * OpenSaveMRU
    * Recents Docs
    * Services
    * Shellbags
    * Autoruns
    * USB History
    * Userassists
    * Networks List

  * memory
    * Clipboard
    * dlls loaded
    * Opened Files

  * dump
    * MFT (raw or timeline) we use AnalyseMFT for https://github.com/dkovar/analyzeMFT
    * MBR
    * RAM
    * DISK
    * Registry
    * SAM
    
  * FileCatcher
    * based on mime type
    * Define path and depth to filter the search
    * possibility to filter your search
    * Yara Rules
    
The full documentation can be download here: https://github.com/SekoiaLab/Fastir_Collector/blob/master/documentation/FastIR_Documentation.pdf

A post about FastIR Collector and advanced Threats can be consulted here:  http://www.sekoia.fr/blog/fastir-collector-on-advanced-threats

with the paper:  http://www.sekoia.fr/blog/wp-content/uploads/2015/10/FastIR-Collector-on-advanced-threats_v1.4.pdf
