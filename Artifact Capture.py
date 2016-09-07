## ----------------------------------------------------------------------------------------------------------------------------------------
##	Python Artifact Collection Script for use with Carbon Black Enterprise Response
##
##  Version 1.0
##
##  This Powershell script is updated to follow the collection process modelled by Corey Harrell's
##  TR3Secure Data Collection Script: http://journeyintoir.blogspot.com/2013/09/tr3secure-data-collection-script.html and
##  https://code.google.com/p/jiir-resources/downloads/list
##
##	References
##		Malware Forensics: Investigating and Analyzing Malicious Code by Cameron H. Malin, Eoghan Casey, and James M. Aquilina
## 		Windows Forensics Analysis (WFA) Second Edition by Harlan Carvey
## 		RFC 3227 - Guidelines for Evidence Collection and Archiving http://www.faqs.org/rfcs/rfc3227.html
##		Dual Purpose Volatile Data Collection Script http://journeyintoir.blogspot.com/2012/01/dual-purpose-volatile-data-collection.html
##		Corey Harrell (Journey Into Incident Response)
##		Sajeev.Nair - Nair.Sajeev@gmail.com	Live Response Script Desktop
##
##		Other contributors are mentioned in the code where applicable
##
##	Copyright 2016 Jeff Rotenberger
##
## ----------------------------------------------------------------------------------------------------------------------------------------
##
##
## ----------------------------------------------------------------------------------------------------------------------------------------

## ----------------------------------------------------------------------------------------------------------------------------------------
## Set Target
## ----------------------------------------------------------------------------------------------------------------------------------------

import time

from cbapi.response import CbEnterpriseResponseAPI, Sensor

c = CbEnterpriseResponseAPI()

print("Enter Sensor ID")
name = raw_input()
sensor_id = name
sensor = c.select(Sensor, sensor_id)


with sensor.lr_session() as session:          # this will wait until the Live Response session is established
    session.put_file(open("\\\\DIRECTORY\\artifactpullcb.ps1", "rb"),"c:\\windows\\CarbonBlack\\artifactpullcb.ps1")
    session.create_process("PowerShell SET-EXECUTIONPOLICY UNRESTRICTED")
    output = session.create_process("PowerShell .\\artifactpullcb.ps1")
    session.create_process("PowerShell SET-EXECUTIONPOLICY RESTRICTED")
    time.sleep(1000)
    print output
# add line to delete ps1 file after completion
