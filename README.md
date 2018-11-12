I am by no means a python programmer.  I threw this together for the SANS572 Capstone.  You are 
free to use these as needed, make modifications, etc.  

Feedback, corrections, suggestions, questions, whatever, drop me an email:  xnih13@gmail.com

---

Before you being...  
You'll need tshark installed on the system and pyshark.  
pyshark is normally fairly simple to install.  sudo pip install pyshark

I would also HIGHLY recommend you change your time over to UTC on the system you'll be running the scripts from!

---

smbParser.py 
- main file that goes through and looks at what is going on in the SMB traffic.  The current version 
only outputs in "raw" format, which is more for human readability, a future version will hopefully 
provide some type of csv and/or json.  There are a number of command line options to provide smaller
chunks of info that I needed at the time, future builds will have even more (assuming I get to it).

Example(s):
- python smbParser.py -i=stark-smb.pcap -cs=both -f="(ip.src==10.0.10.100 and ip.dst==10.0.10.101) or (ip.src==10.0.10.101 and ip.dst==10.0.10.102)"
- python smbParser.py -i=stark-smb.pcap -cs=server
- python smbParser.py -i=stark-smb.pcap -n
- python smbParser.py -i=stark-smb.pcap -n -f="ip.dst==10.0.10.102"
- python smbParser.py -i=stark-smb.pcap -fl
- python smbParser.py -i=stark-smb.pcap -fl -f="ip.src==10.0.10.100"
- python smbParser.py -i=stark-smb.pcap
- python smbParser.py -i=stark-smb.pcap -f="ip.dst==10.0.10.101"

Options:
-n = native, as in native LANMAN and native OS.  Useful if all you want to do is determine what the OS is.  Future version will hopefully have a OS fingerprint piece.
-fl = file list.  Added prior to smbFileList.py, but different format anyway, more useful to see searches and other tidbits.
-cs = list of client/server initial setups.  Interesting oddities where system times may not be the same.  Also lets you see who is making all the connection attempts

Output:
{'filter': 'smb', 'input': 'stark-smb.pcap', 'clientServer': None, 'fileList': False, 'native': False}
10.0.0.7 -> 10.0.0.6 (1999-12-15 12:52:29.723691)
  Client is: 10.0.0.7
10.0.0.6 -> 10.0.0.7 (1999-12-15 12:52:29.724411)
  Success
  Server is: 10.0.0.6
    System Time: Apr  2, 2012 12:52:25.464258900 UTC
    System TimeZone is: 240
10.0.0.7 -> 10.0.0.6 (1999-12-15 12:52:29.739580)
  Version:  5.1 (2600); NTLM Revision 15
  Native OS: Windows 2002 Service Pack 3 2600
  Native Lanman: Windows 2002 5.1
10.0.0.6 -> 10.0.0.7 (1999-12-15 12:52:29.740082)
  More Processing Required
  Targetted Name: MTNDEW
  NTLM Server Challenge: 03:22:e6:ab:c9:aa:78:e0
  Version:  6.1 (7601); NTLM Revision 15
  Native OS: Windows 7 Ultimate 7601 Service Pack 1
  Native Lanman: Windows 7 Ultimate 6.1
10.0.0.7 -> 10.0.0.6 (1999-12-15 12:52:29.742229)
  Lan Manager Response: 00
  Version:  5.1 (2600); NTLM Revision 15
  NULL Connection
  Domain: NULL
  User: NULL
  Hostname: MD-32
  Native OS: Windows 2002 Service Pack 3 2600
  Native Lanman: Windows 2002 5.1
10.0.0.6 -> 10.0.0.7 (1999-12-15 12:52:29.742890)
  Success
  Native OS: Windows 7 Ultimate 7601 Service Pack 1
  Native Lanman: Windows 7 Ultimate 6.1
10.0.0.7 -> 10.0.0.6 (1999-12-15 12:52:29.788609)
  Tree Connect Request
    TID: 0 (\\MD-764\IPC$)
    PID: 65279
    UID: 2048
    MID: 192
    Path: \\MD-764\IPC$
      Service: ?????
10.0.0.6 -> 10.0.0.7 (1999-12-15 12:52:29.788818)
  Success
  Tree Connect Successful
    Share Access Rights: 001fffff
    Guest Share Access Rights: 001fffff
    TID: 2048 (\\MD-764\IPC$)
    PID: 65279
    UID: 2048
    MID: 192
    Path: \\MD-764\IPC$
      Service: IPC

---

smbFileList.py 
- looks for file reads or writes in a set of smb packets.  If it finds any it will provide you with 
the wireshark/tshark display filter for that file.  This could be used for just looking in wireshark 
at it closer, but is designed to be fed into smbCarver.py.

Example(s):
- python smbFileList.py -i=somefile.pcap | sort | uniq > filelist.txt
- python smbFileList.py -i=somefile.pcap -f="smb.cmd == 0x2e" | sort | uniq > readList.txt
- python smbFileList.py -i=somefile.pcap -f="smb.cmd == 0x2f" | sort | uniq > writeList.txt

Results will look something like this:
(smb.cmd == 46) && (smb.tid == 163) && (smb.fid == 1697) && (smb.path == "\\\\CONT\\IPC$") && (smb.file == "\\lsarpc")
(smb.cmd == 46) && (smb.tid == 163) && (smb.fid == 1698) && (smb.path == "\\\\CONT\\IPC$") && (smb.file == "\\samr")
(smb.cmd == 46) && (smb.tid == 163) && (smb.fid == 1699) && (smb.path == "\\\\CONT\\IPC$") && (smb.file == "\\winreg")

This could be simplified down to these 3 attributes when fed into smbCarver:
smb.cmd
smb.tid
smb.fid

But I wanted to know what file/path these were to make sure it was what I really was looking for.

---

smbCarver.py 
- Take a single line from the smbFile.py output and feed it to this as the filter and pipe it out to 
the file you want and potentially get the extracted file from the packet capture.  Limitations are 
that it does not do any error checking.  If a packet is sent twice, missing, sent out of order, etc, 
your extract will be worthless, but assuming a "clean" network and a full capture, it should work fine.

Example(s):
- python smbCarver.py -i=stark-smb.pcap -f="(smb.cmd == 46) && (smb.tid == 634) && (smb.fid == 3277) && (smb.path == "\\CONT\IPC$") && (smb.file == "\lsarpc")" > lsarpc
- python smbCarver.py -i=stark-smb.pcap -f='(smb.cmd == 46) && (smb.tid == 163) && (smb.fid == 1699) && (smb.path == "\\\\CONT\\IPC$") && (smb.file == "\\winreg")' > winreg
 
Long term it is probably simpler to shorten this down to '(smb.cmd == 46) && (smb.tid == 634) && (smb.fid == 3277)' as smb.path and smb.file should tie back to those.

Output:
If there are no bad or missing packets, you should get a file out of this.  There is plenty of room for improvement, but as a quick export this works in most cases.
