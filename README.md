# FastIR Collector

## Concepts
This tool collects different artefacts on live Windows and records the results in csv or json files. With the analyses
of these artefacts, an early compromission can be detected.

## Requirements
- pywin32
- python WMI
- python psutil
- python yaml
- construct
- distorm3
- hexdump
- pytz

Alternatively, a `pip freeze` output is available in `reqs.pip`.

## Compiling
To compile FastIR, you will need [pyinstaller](https://github.com/pyinstaller/pyinstaller).
Simply use ```pyinstaller pyinstaller.spec``` at the project root directory.
The binary will by default be in `/dist`.

Important: for x64 systems, check that your local python installation is also
in x64.

## Execution
- `./fastIR_x64.exe -h` for help
- `./fastIR_x64.exe --packages fast` extract all artefacts except dump and FileCatcher packages'
- `./fastIR_x64.exe --packages dump --dump mft` to extract MFT
- `./fastIR_x64.exe --packages all --output_dir your_output_dir` to set the directory output
(by default `./output/`)
- `./fastIR_x64.exe --profile you_file_profile` to set your own profile extraction

## Packages
Packages List and Artefacts:

  * fs
    * IE/Firefox/Chrome History
    * IE/Firefox/Chrome Downloads
    * Named Pipes
    * Prefetch
    * Recycle-bin

  * health
    * ARP Table
    * Drives List
    * Network Drives
    * Network Cards
    * Processes
    * Routing Table
    * Tasks
    * Scheduled Jobs
    * Services
    * Sessions
    * Network Shares
    * Sockets

  * registry
    * Installer Folders
    * OpenSaveMRU
    * Recent Docs
    * Services
    * Shellbags
    * Autoruns
    * USB History
    * UserAssists
    * Networks List

  * memory
    * Clipboard
    * Loaded DLLs
    * Opened Files

  * dump
    * MFT (raw or timeline) we use [AnalyseMFT](https://github.com/dkovar/analyzeMFT)
    * MBR
    * RAM
    * DISK
    * Registry
    * SAM
    
  * FileCatcher
    * Based on mime type
    * Define path and depth to filter the search
    * Possibility to filter your search
    * Yara Rules
    
The full documentation can be downloaded [here](https://github.com/SekoiaLab/Fastir_Collector/blob/master/documentation/FastIR_Documentation.pdf).

A post about FastIR Collector and advanced Threats can be consulted [here](http://www.sekoia.fr/blog/fastir-collector-on-advanced-threats)
with its [white paper](http://www.sekoia.fr/blog/wp-content/uploads/2015/11/FastIR-Collector-on-advanced-threats_v1.5.pdf).

