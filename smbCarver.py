import argparse, sys
import pyshark #pip install pyshark

def getReadAndX (pkt):
  try:
    flag = int(getattr(pkt.smb, 'smb.flags.response'))

    if flag == 1:  
      try:
        data = pkt.data.data.binary_value
        print(data)
        sys.stdout.write(data)
      except AttributeError as e:
        try:
          data = pkt.smb.file_data.binary_value
          sys.stdout.write(data)
        except AttributeError as e:
          pass
        pass

  except AttributeError as e:
    pass


def getCommWrite (pkt):
  try:
    flag = int(getattr(pkt.smb, 'smb.flags.response'))

    if flag == 0:  
      try:
        data = pkt.data.data.binary_value
        print(data)
        sys.stdout.write(data)
      except AttributeError as e:
        try:
          data = pkt.smb.file_data.binary_value
          sys.stdout.write(data)
        except AttributeError as e:
          pass
        pass

  except AttributeError as e:
    pass


def get_args():
  parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description='Information:\n-Requires thark and pyshark to be installed. \n-Does not like very large pcaps, keep to under 1GB or risk running out of swap space.\n-HIGHLY recommend local system time is set to UTC!', epilog='Example(s): \n python smbCarver.py -i=stark-smb.pcap -f="(smb.cmd == 46) && (smb.tid == 6342) && (smb.fid == 3277) && (smb.path == "\\\\CONTROLLER\\IPC$") && (smb.file == "\\lsarpc")" > lsarpc \n python smbCarver.py -i=stark-smb.pcap -f=\'(smb.cmd == 47) && (smb.tid == 204) && (smb.fid == 3278) && (smb.path == "\\\\10.0.0.98\\C$") && (smb.file == "\\windows\\system32\\dllhost\\somefile.dll")\' > somefile.dll \n Sometimes you may need to check the output against wireshark directly as in 2 above one.  In the somefile one the file it was writing to was somefile.dll, but need to modify it slightly to make work (drop the smb.file section).  Key xlsx, docx, exe files normally work fine with the smb.file listed, but you will need to run testing as needed')
  parser.add_argument('-i', '--input', help='filename to open', required=True)
  parser.add_argument('-f', '--filter', help='filter to use', required=True)
  args = vars(parser.parse_args())
  return args


args = get_args()
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

