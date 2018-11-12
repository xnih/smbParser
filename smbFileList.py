#
# use at own risk
# no 
#
import argparse
import pyshark #pip install pyshark 

def getReadAndX (pkt):
  try:
    flag = int(getattr(pkt.smb, 'smb.flags.response'))
    if flag == 1:
      try:
        cmd = pkt.smb.cmd
      except AttributeError as e:
        cmd = ''
        pass
      try:
        file = pkt.smb.file
        file = file.replace("\\", "\\\\")
      except AttributeError as e:
        file = ''
        pass
      try:
        fid = pkt.smb.fid
      except AttributeError as e:
        fid = ''
        pass
      try:
        path = pkt.smb.path
        path = path.replace("\\", "\\\\")
      except AttributeError as e:
        path = ''
        pass
      try:
        tid = pkt.smb.tid
      except AttributeError as e:
        tid = ''
        pass
      print '(smb.cmd == %s) && (smb.tid == %s) && (smb.fid == %s) && (smb.path == "%s") && (smb.file == "%s")' % (cmd, tid, fid, path, file)
  except AttributeError as e:
    pass 

def getCommWrite (pkt):
#for now identical to Read, not sure if there are differences that need tweaked later
  try:
    flag = int(getattr(pkt.smb, 'smb.flags.response'))
    if flag == 1:
      try:
        cmd = pkt.smb.cmd
      except AttributeError as e:
        cmd = ''
        pass
      try:
        file = pkt.smb.file
        file = file.replace("\\", "\\\\")
      except AttributeError as e:
        file = ''
        pass
      try:
        fid = pkt.smb.fid
      except AttributeError as e:
        fid = ''
        pass
      try:
        path = pkt.smb.path
        path = path.replace("\\", "\\\\")
      except AttributeError as e:
        path = ''
        pass
      try:
        tid = pkt.smb.tid
      except AttributeError as e:
        tid = ''
        pass
      print '(smb.cmd == %s) && (smb.tid == %s) && (smb.fid == %s) && (smb.path == "%s") && (smb.file == "%s")' % (cmd, tid, fid, path, file)
  except AttributeError as e:
    pass 

def get_args():
  parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description='Information:\n-Requires thark and pyshark to be installed. \n-Does not like very large pcaps, keep to under 1GB or risk running out of swap space.\n-HIGHLY recommend local system time is set to UTC!', epilog='Example(s): \n  python smbFileList.py -i=somefile.pcap | sort | uniq > filelist.txt \n  python smbFileList.py -i=somefile.pcap -f="smb.cmd == 0x2e" | sort | uniq > readList.txt \n  python smbFileList.py -i=somefile.pcap -f="smb.cmd == 0x2f" | sort | uniq > writeList.txt')
  parser.add_argument('-i', '--input', help='filename to open', required=True)
  parser.add_argument('-f', '--filter', help='filter to use', default='smb', required=False)
  args = vars(parser.parse_args())
  return args

args = get_args() 
print args 
pcap=args['input'] 
filter=args['filter'] 
cap = pyshark.FileCapture(pcap, display_filter=filter) 
for pkt in cap:
  try:
    cmd = int(pkt.smb.cmd)
  except AttributeError as e:
    cmd = '-1'
    pass
  if cmd == 46: #2e
    getReadAndX(pkt)
  elif cmd == 47: #2f
    getCommWrite(pkt)
