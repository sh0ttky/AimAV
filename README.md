# AimAV
AimAV is an open source Minimal high performance antivirus engine designed for detecting and disinfecting malware.


## How it works:

The program runs through a given directory ( extracts archives to 4 nested archives depth ) scans for each file SHA and compares the found SHA signatures with the vx underground open data base. this program also outputs two files, the first one is named database.txt, which is a custom database with the found threats SHA checksums this database is used in future scans as a first source of information before attempting to reach the vx underground dataset in order to reduce scan durations by priorizing the local database over the remote one, it also outputs an "output.txt" file with the scan results durations and more informations about the scaneed folder or file 
