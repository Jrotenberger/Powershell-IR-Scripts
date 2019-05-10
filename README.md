# Powershell-IR-Scripts
# ArtifactPull.ps1 is initial commit
# Tools contains list of tools referenced.

UPDATED 5/10/2019

NEW NEW NEW

I updated the script (it was a long time coming).

CHANGES: 

1) No extra PS modules are needed.  For the most part these got rolled in the main script
2) The external tools needed have been dramatically decreased.  The majority have been replicated by Powershell capabilities since the orginal script was written.
3) The memory capture portion of the script is commented out by default.  If you want it as part of this script, you'll need to remove the '#" on lines 212/213.


I've been using variations of this script for going on 3 years now and its always served me very well.  The inspiration comes from 
Corey Harrell who had a similar Perl script.

Since I didn't know Perl and it didn't really suit our environment, I modified his to work in Powershell and now we deploy it via
Carbon Black but it can still be used as a stand alone.

Credit for different sections of code are documented in the script.

Lines 30, 77, and 83 need to be adjusted for your environment
