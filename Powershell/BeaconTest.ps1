## ----------------------------------------------------------------------------------------------------------------------------------------
##	Beaconing Test Script
##
##  Version 0.1
##
##  This Powershell script is designed to grab the number of links on a designated site at a predetermined interval.  It will
##  continue until hard stopped.  It is for use in determine whether beaconing behavior can be detected.
##
##	Copyright 2016 Jeff Rotenberger 
##
## ----------------------------------------------------------------------------------------------------------------------------------------

## Loop

While(1)
{

## file to save beacon results

$file = "C:\google.txt"

## Get datetime

date | select DateTime | OutFile $file -append


## Grab link total

(invoke-webrequest -uri 'http://www.google.com').links.count | OutFile $file -append

## wait 5 minutes

Start-sleep -seconds 300


## end loop
}