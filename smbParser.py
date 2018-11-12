import argparse, datetime
import pyshark #pip install pyshark

def getClose (pkt):
  try:
    flag = int(getattr(pkt.smb, 'smb.flags.response'))

    if flag == 0:
      print('  Close Request')
    elif flag == 1:
      try:
        statusCode = hex(int(pkt.smb.nt_status))
        if statusCode == '0x0':
          print('  Close Completed')
        else:
          print('  something may have failed in close.  Status Code: %s' % statusCode)
      except AttributeError as e:
        pass
    else:
      print('Error in smb.flags.response?')
  except AttributeError as e:
    pass


def getCreateAndX (pkt):
  try:
    flag = int(getattr(pkt.smb, 'smb.flags.response'))

    if flag == 0:
      try:
        rights = int(getattr(pkt.smb, 'smb.impersonation.level'))
        if rights == 0:
          print('  Rights 0')
        elif rights == 1:
          print('  Rights 1')
        elif rights == 2:
          print('  Rights Impersonation')
        elif rights == 3:
          print('  Rights 3')
        elif rights == 3:
          print('  Rights 3')
        else:
          print('  Rights %s' % rights)
      except AttributeError as e:
        pass
    elif flag == 1:
      try:
        fileOpen = int(getattr(pkt.smb, 'smb.create.action'))
        if fileOpen == 0:
          print('  File Did not exist, so created?????')
        elif fileOpen == 1:
          print('  File existed and was opened')
      except AttributeError as e:
        pass
    else:
      print('Error in smb.flags.response?')
  except AttributeError as e:
    pass



def getTransOperation (pkt):
  try:
    flag = int(getattr(pkt.smb, 'smb.flags.response'))

    try:
      opnum = int(pkt.svcctl.opnum)
    except AttributeError as e:
      opnum = -1
      pass

    if flag == 0:
      try:
        if opnum == -1:
          pass
        elif opnum == 0:
          print('  CloseServiceHandle request')
        elif opnum == 1:
          print('  Control Service request')
        elif opnum == 2:
          print('  Delete Service request')
        elif opnum == 6:
          print('  QueryServiceW request')
        elif opnum == 12:
          print('  CreateServiceW request')
          try:
            serviceName = pkt.svcctl.servicename
            print('      Service Name: %s' % serviceName)
          except AttributeError as e:
            pass
          try:
            displayName = pkt.svcctl.displayname
            print('      Display Name: %s' % displayName)
          except AttributeError as e:
            pass
          try:
            accessMask = int(pkt.svcctl.access_mask)
            print('      Access Mask: 0x%08x' % accessMask)
          except AttributeError as e:
            pass
          try:
            serviceType = int(pkt.svcctl.service_type)
            print('      Service Type: 0x%08x' % serviceType)
            #need to look at service start type and control info also later
          except AttributeError as e:
            pass
          try:
            binaryPathname = pkt.svcctl.binarypathname
            print('      Binary Pathname: %s' % binaryPathname)
            #need to look at load order, dependencies, service start name, password, etc, may be able to collect useful info from wire?
          except AttributeError as e:
            pass
        elif opnum == 13:
          print('  EnumDependentServicesW')
        elif opnum == 14:
          print('  EnumServicesStatusW')
        elif opnum == 15:
          print('  OpenSCManagerW request')
          try:
            machineName = pkt.svcctl.machinename
            print('      Machine Name: %s' % machineName)
          except AttributeError as e:
            pass
#          try:
#            maxCount = int(getattr(pkt.smb, 'dcerpc.array.max_count'))
#            print '      Max Count: %s' % maxCount
#          except AttributeError as e:
#            pass
#          try:
#            actualCount = int(getattr(pkt.smb, 'dcerpc.array.actual_count'))
#            print '      Actual Count: %s' % actualCount
#          except AttributeError as e:
#            pass
          try:
            accessMask = int(pkt.svcctl.access_mask)
            print('      Access Mask: 0x%08x' % accessMask)
          except AttributeError as e:
            pass

        elif opnum == 16:
          print('  OpenServiceW request')
          try:
            serviceName = pkt.svcctl.servicename
            print('      Service Name: %s' % serviceName)
          except AttributeError as e:
            pass
          try:
            accessMask = int(pkt.svcctl.access_mask)
            print('      Access Mask: %08x' % accessMask)
          except AttributeError as e:
            pass
        elif opnum == 17:
          print('  QueryServiceConfigW request')
        elif opnum == 19:
          print('  StartServiceW request')
        elif opnum == 39:
          print('  QueryServiceConfig2W request')
        else:
          print('  Unknown OpNum: %s' % opnum)
      except AttributeError as e:
        pass
    elif flag == 1:
      #https://infosys.beckhoff.com/english.php?content=../content/1033/tcdiagnostics/html/tcdiagnostics_win32_errorcodes.htm&id=
      try:
        statusCode = hex(int(pkt.svcctl.rc))
        if statusCode == '0x0':
          print('  Trans process return code indicates success')
        elif statusCode == '0x00000431':
          print('  Trans Service already exists')
        else:
          print('  Return code: %s' % statusCode)

      except AttributeError as e:
        pass
    else:
      print('Error in smb.flags.response?')
  except AttributeError as e:
    pass



def getTrans (pkt):
  try:
    flag = int(getattr(pkt.smb, 'smb.flags.response'))
    #may be worth grabbign create/access/file attributes, but ignoring for now.  
    #need to eventually look at DCE/RPC chunk also.

    try:
      transName = pkt.smb.trans_name
      print('  Trans Name: %s' % transName)
    except AttributeError as e:
      pass

    getTransOperation(pkt)

    if flag == 0:
      try:
        pass
      except AttributeError as e:
        pass
    elif flag == 1:
      try:
        pass
      except AttributeError as e:
        pass
    else:
      print('Error in smb.flags.response?')
  except AttributeError as e:
    pass


def getShareAccess (pkt):
  try:
    flag = int(getattr(pkt.smb, 'smb.flags.response'))
    if flag == 0:
      try:
#        query = int(pkt.smb.share_access)
        query = pkt.smb.share_access
        if query == '0x00000000':
          print('  Share Rights:  Requested 0 - Bind?')
        elif query == '0x00000001':
          print('  Share Rights:  Requested Read')
        elif query == '0x00000002':
          print('  Share Rights:  Requested 2')
        elif query == '0x00000003':
          print('  Share Rights:  Requested Read/Write')
        elif query == '0x00000004':
          print('  Share Rights:  Requested 4')
        elif query == '0x00000005':
          print('  Share Rights:  Requested 5')
        elif query == '0x00000006':
          print('  Share Rights:  Requested 6')
        elif query == '0x00000007':
          print('  Share Rights:  Requested Read/Write/Delete')
        else:
          print('  Share Rights:  Requested %s' % query)
      except AttributeError as e:
        pass
    elif flag == 1:
      pass
    else:
      print('Error in smb.flags.response?')
  except AttributeError as e:
    pass



def getStatusCode (pkt):
  try:
    flag = int(getattr(pkt.smb, 'smb.flags.response'))
    if flag == 0:
      pass
    elif flag == 1:
      try:
        statusCode = hex(int(pkt.smb.nt_status))
        if statusCode == '0x0':
          print('  Success')
        elif statusCode == '0x80000005':
          print('  Buffer Overflow')
        elif statusCode == '0xc000000f':
          print('  No Such File')
        elif statusCode == '0xc0000016':
          print('  More Processing Required')
        elif statusCode == '0xc0000022':
          print('  Access Denied')
        elif statusCode == '0xc0000034':
          print('  Object Not Found')
        elif statusCode == '0xc0000035':
          print('  Object Name Collision')
        elif statusCode == '0xc000003a':
          print('  Object Path Not Found')
        elif statusCode == '0xc0000043':
          print('  Sharing Violoation')
        elif statusCode == '0xc0000054':
          print('  File Lock Conflict')
        elif statusCode == '0xc000006d':
          print('  Logon Failure')
        elif statusCode == '0xc00000b0':
          print('  PIPE Disconnected')
        elif statusCode == '0xc0000120':
          print('  Cancelled')
        elif statusCode == '0xc0000225':
          print('  Status Not Found')
        else:
          print('  Unknown Status Code: %s' % statusCode)
      except AttributeError as e:
        pass
    else:
      print('Error in smb.flags.response?')
  except AttributeError as e:
    pass


def getLocking (pkt):
  #smb.cmd = 0x24
  try:
    data = int(getattr(pkt.smb, 'smb.lock.type'))
    print('  File Lock Type Attempted %s' % data)
  except AttributeError as e:
    pass

  try:
    oplock = int(getattr(pkt.smb, 'smb.oplock.level'))
    if oplock == 0:
      print('  File Lock:  no')
    elif oplock == 2:
      print('  File Lock:  yes')
    else:
      print('  Unknown File Lock attribute: %s' % oplock)
  except AttributeError as e:
    pass

def clientServer (pkt, search):
  #Determine Client/Server info from smb.cmd = 0x72
  try:
    flag = int(getattr(pkt.smb, 'smb.flags.response'))

    if (flag == 1 and (search == 'server' or search == 'both')):
      print('  Server is: %s' % pkt.ip.src)
      timeinfo = getattr(pkt.smb, 'smb.system.time')
      print('    System Time: %s' % timeinfo)
      time = pkt.smb.server_timezone
      print('    System TimeZone is: %s' % (time))
    elif (flag == 0 and (search == 'client' or search == 'both')):
      print('  Client is: %s' % pkt.ip.src)
      #determine how to get the text data later and get the requested dialects to potentially do OS Fingerprinting on.
  except AttributeError as e:
    pass

def getOpenAndX (pkt):
  try:
    flag = int(getattr(pkt.smb, 'smb.flags.response'))

    if flag == 0:  #requested
      print('  Extended File Open Requested')
    elif flag == 1:  #response
      try:
        statusCode = hex(int(pkt.smb.nt_status))
        if statusCode == '0x0':
          print('  Extended File Open Completed')
      except AttributeError as e:
        print('  Something may have failed in attempt.  ')
        pass

    getFileFlags(pkt)
    getIdInfo(pkt)

  except AttributeError as e:
    pass


def getCommRead (pkt):
  try:
    flag = int(getattr(pkt.smb, 'smb.flags.response'))

    if flag == 0:  #requested
      print('  Comm Read Requested')
    elif flag == 1:  #response
      try:
        statusCode = hex(int(pkt.smb.nt_status))
        if statusCode == '0x0':
          print('  Comm Read Completed')
      except AttributeError as e:
        print('  Something may have failed in attempt.  ')
        pass

    getFileFlags(pkt)
    getIdInfo(pkt)

  except AttributeError as e:
    pass

def getCommWrite (pkt):
  try:
    flag = int(getattr(pkt.smb, 'smb.flags.response'))

    if flag == 0:  #requested
      print('  Comm Write Requested')
    elif flag == 1:  #response
      try:
        statusCode = hex(int(pkt.smb.nt_status))
        if statusCode == '0x0':
          print('  Comm Write Completed')
      except AttributeError as e:
        print('  Something may have failed in attempt.')
        pass

    getFileFlags(pkt)

    getIdInfo(pkt)

  except AttributeError as e:
    pass

def getFileFlags(pkt):
  try:
    smbFile = pkt.smb.file
  except AttributeError as e:
    pass

  try:
    path = pkt.smb.path
  except AttributeError as e:
    pass

  try:
    flag = int(getattr(pkt.smb, 'smb.flags.response'))

    if flag == 0:  #requested

      try:
        disposition = int(getattr(pkt.smb, 'smb.create.disposition'))
        if disposition == 1:
          print('  Attempt to Open File:  %s%s' % (path, smbFile))
      except AttributeError as e:
        pass
 
      try:
        disposition2 = int(getattr(pkt.smb, 'smb.disposition.delete_on_close'))
        if disposition2 == 1:
          print('  Attempting to Delete on File Close')
      except AttributeError as e:
        pass

    elif flag == 1:  #response
      pass
  except AttributeError as e:
    pass

  try:
#    createFlags = int(pkt.smb.create_flags)
#    print('    Create Flags: %08x' % createFlags)
    createFlags = pkt.smb.create_flags
    print('    Create Flags: %s' % createFlags)
  except AttributeError as e:
    pass

  try:
#    accessMask = int(pkt.smb.access_mask)
#    print('    Access Mask: %08x' % accessMask)
    accessMask = pkt.smb.access_mask
    print('    Access Mask: %s' % accessMask)
  except AttributeError as e:
    pass

  try:
#    fileAttributes = int(pkt.smb.file_attribute)
#    print('    File Attributes: %08x' % fileAttributes)
    fileAttributes = pkt.smb.file_attribute
    print('    File Attributes: %s' % fileAttributes)
  except AttributeError as e:
    pass

  try:
#    shareAccess = int(pkt.smb.share_access)
#    print('    Share Access: %08x' % shareAccess)
    shareAccess = pkt.smb.share_access
    print('    Share Access: %s' % shareAccess)
  except AttributeError as e:
    pass

  try:
#    createOptions = int(pkt.smb.create_options)
#    print('    Create Options: %08x' % createOptions)
    createOptions = pkt.smb.create_options
    print('    Create Options: %s' % createOptions)
  except AttributeError as e:
    pass


def getIdInfo(pkt):

  try:
    path = pkt.smb.path
  except AttributeError as e:
    path = ''
    pass

  try:
    file = pkt.smb.file
  except AttributeError as e:
    file = ''
    pass

  try:
    tid = pkt.smb.tid
    print('    TID: %s (%s)' % (tid, path))
  except AttributeError as e:
    pass

  try:
#    fid = int(pkt.smb.fid)
#    print('    FID: 0x%04x (%s)' % (fid, file))
    fid = pkt.smb.fid
    print('    FID: 0x%s (%s)' % (fid, file))
  except AttributeError as e:
    pass

  try:
    pid = pkt.smb.pid
    print('    PID: %s' % pid)
  except AttributeError as e:
    pass

  try:
    uid = pkt.smb.uid
    print('    UID: %s' % uid)
  except AttributeError as e:
    pass

  try:
    mid = pkt.smb.mid
    print('    MID: %s' % mid)
  except AttributeError as e:
    pass


def getTreeDisconnects (pkt):
  try:
      flag = int(getattr(pkt.smb, 'smb.flags.response'))

      if flag == 0:  #requested
        print('  Tree Disconnect Requested')
      elif flag == 1:  #response
        try:
          statusCode = hex(int(pkt.smb.nt_status))
          if statusCode == '0x0':
            print('  Tree Disconnect Completed')
        except AttributeError as e:
          print('  Something may have failed in attempt.' )
          pass

      getIdInfo(pkt)

  except AttributeError as e:
    pass

def getLogoffs (pkt):
  try:
      flag = int(getattr(pkt.smb, 'smb.flags.response'))
    
      if flag == 0:  #requested
        print('  Logoff Requested')
      elif flag == 1:  #response
        try:
          statusCode = hex(int(pkt.smb.nt_status))
          if statusCode == '0x0':
            print('  Logoff Completed')
        except AttributeError as e:
          print('  Something may have failed in attempt.')
          pass

      getIdInfo(pkt)

  except AttributeError as e:
    pass


def getTreeConnects (pkt):
  try:
      flag = int(getattr(pkt.smb, 'smb.flags.response'))

      if flag == 0:  #request
        print('  Tree Connect Request')
      elif flag == 1:  #response
        try:
          statusCode = hex(int(pkt.smb.nt_status))
          if statusCode == '0x0':
            print('  Tree Connect Successful')
        except AttributeError as e:
          print('  Something may have failed in attempt.')
          pass

        try:
          password = pkt.smb.password
          print('      Password: %s' % password)
        except AttributeError as e:
          pass

        try:
#          accessMask = int(pkt.smb.get_field_by_showname('Access Mask').all_fields[0].show)
#          print('    Share Access Rights: %08x' % accessMask)
          accessMask = pkt.smb.get_field_by_showname('Access Mask').all_fields[0].show
          print('    Share Access Rights: %s' % accessMask)
        except AttributeError as e:
          pass

        try:
#          accessMask = int(pkt.smb.get_field_by_showname('Access Mask').all_fields[1].show)
#          print('    Guest Share Access Rights: %08x' % accessMask)
          accessMask = pkt.smb.get_field_by_showname('Access Mask').all_fields[1].show
          print('    Guest Share Access Rights: %s' % accessMask)
        except AttributeError as e:
          pass

      elif flag == 0:  #request
        pass  #at least for now, nothing needed here.

      getIdInfo(pkt)

      try:
        path = pkt.smb.path
        print('    Path: %s' % path)
      except AttributeError as e:
        pass

      try:
        service = pkt.smb.service
        print('      Service: %s' % service)
      except AttributeError as e:
        pass


  except AttributeError as e:
    pass

def getFileInfo(pkt):
  try:
    flag = int(getattr(pkt.smb, 'smb.flags.response'))

    if flag == 0:  #requested
      try:
        #https://www.samba.org/samba/devel/smbtorture-raw-functions.txt
        query = int(pkt.smb.qpi_loi)
        if query == 258:
          print('    Query File Standard Info')
        elif query == 1004:
          print('    Query File Basic Info')
        elif query == 1005:  #what is different than 258?
          print('    Query File Standard Info')
        elif query == 1006:
          print('    Query File Internal Info')
        elif query == 1007:
          print('    Query File EA Info')
        elif query == 1022:
          print('    Query File Stream Info')
        elif query == 1034:
          print('    Query File Network Open Info')
        else:
          print('    Unknown option %s' % query)
      except AttributeError as e:
        pass

      try:  #should look at subcommand and verify it is 0x0001 first, but short cutting it for now since the try/except will bail out, bad form tho
        pattern = pkt.smb.search_pattern
      except AttributeError as e:
        pattern = ''
        pass

      try:
        path = pkt.smb.path
        try:
          smbFile = pkt.smb.file
          if smbFile == '0000':
            smbFile = ''
        except AttributeError as e:
          smbFile = ''
          pass

        print('  Path: %s%s%s' % (path, smbFile, pattern))  #bit of a kludge, but should work
      except AttributeError as e:
        pass

    elif flag == 1:  #response
      pass

  except AttributeError as e:
    pass

  try:
    searchCount = int(pkt.smb.search_count)
#    searchCount = int(pkt.smb.wct)
    print('  Search Count: %s' % searchCount)
    for x in range (0, searchCount):
      try:
#        fileName = pkt.smb.get_field_by_showname('File Name')
        fileSize = int(pkt.smb.get_field_by_showname('Allocation Size').all_fields[x].show)
        fileName = pkt.smb.file.all_fields[x].show   #.show will give the value
        if fileSize == 0:
          print('  Dir: %s' % fileName)
        else:
          print('  File: %s' % fileName)
      except Exception as e:
        pass

      try:
        createTime = pkt.smb.get_field_by_showname('Created').all_fields[x].show
        print('    Create Time: %s' % createTime)
      except AttributeError as e:
        pass

      try:
        accessLast = pkt.smb.get_field_by_showname('Last Access').all_fields[x].show
        print('    Last Access: %s' % accessLast)
      except AttributeError as e:
        pass

      try:
        lastWrite = pkt.smb.get_field_by_showname('Last Write').all_fields[x].show
        print('    Last Write: %s' % lastWrite)
      except AttributeError as e:
        pass

      try:
        change = pkt.smb.get_field_by_showname('Change').all_fields[x].show
        print('    Change: %s' % change)
      except AttributeError as e:
        pass

      try:
        fileSize = int(pkt.smb.get_field_by_showname('Allocation Size').all_fields[x].show)
        print('    Allocation Size: %d' % fileSize)
      except AttributeError as e:
        pass

      try:
        fileAttributes = int(pkt.smb.file_attribute.all_fields[x].show)
        print('    File Attributes: 0x%08x' % fileAttributes)
      except AttributeError as e:
        pass

  except Exception as e:
    pass

def nativeInfo(pkt):
  try:  
      flag = int(getattr(pkt.smb, 'smb.flags.response'))

      if flag == 1:  #response
        try:
          data = getattr(pkt.smb, 'ntlmssp.challenge.target_name')
          print('  Targetted Name: %s' % data)
        except AttributeError as e:
          pass

        try:
          ntlmServerChallenge = getattr(pkt.smb, 'ntlmssp.ntlmserverchallenge')
          print('  NTLM Server Challenge: %s' % ntlmServerChallenge)
        except AttributeError as e:
          pass

#        try:  #need to look into how to pull this, useless right now
#          data = getattr(pkt.smb, 'ntlmssp.challenge.target_info')
#          print '  Targetted Info: %s' % data.showname
#        except AttributeError as e:
#          pass

      elif flag == 0:  #request

        try:
          ntlmClientChallenge = getattr(pkt.smb, 'ntlmssp.ntlmclientchallenge')
          print('  NTLM Client Challenge: %s' % ntlmClientChallenge)
        except AttributeError as e:
          pass

        try:
          lmResponse = getattr(pkt.smb, 'ntlmssp.auth.lmresponse')
          print('  Lan Manager Response: %s' % lmResponse)
        except AttributeError as e:
          pass

        try:
          ntResponse = getattr(pkt.smb, 'ntlmssp.auth.ntresponse')
          print('  NTLM Response: %s' % ntResponse)
        except AttributeError as e:
          pass

  except AttributeError as e:
    pass

  #this applies to both flag 0 and 1, may need to determine in what cases and limit it to just those    
  try:
#    version = pkt.ntlmssp.version #blows up pyshark no idea why, but underlying data can be found through next few calls, so moving on.
    majorVersion = getattr(pkt.smb, 'ntlmssp.version.major')
    minorVersion = getattr(pkt.smb, 'ntlmssp.version.minor')
    buildNumber = getattr(pkt.smb, 'ntlmssp.version.build_number')
    ntlmCurrentRevision = getattr(pkt.smb, 'ntlmssp.version.ntlm_current_revision')
    print('  Version:  %s.%s (%s); NTLM Revision %s' % (majorVersion, minorVersion, buildNumber, ntlmCurrentRevision))
  except AttributeError as e:
    pass

  try:  
    data = getattr(pkt.smb, 'ntlmssp.auth.username')
    if data == 'NULL':
      print('  NULL Connection')
  except AttributeError as e:
    pass

  try:
    data = getattr(pkt.smb, 'ntlmssp.auth.domain')
    print('  Domain: %s' % data)
  except AttributeError as e:
    pass

  try:
    data = getattr(pkt.smb, 'ntlmssp.auth.username')
    print('  User: %s' % data)
  except AttributeError as e:
    pass

  try:
    data = getattr(pkt.smb, 'ntlmssp.auth.hostname')
    print('  Hostname: %s' % data)
  except AttributeError as e:
    pass

  try:
    if pkt.smb.native_os:
      print('  Native OS: %s' % pkt.smb.native_os)
  except AttributeError as e:
    pass

  try:
    if pkt.smb.native_lanman:
      print('  Native Lanman: %s' % pkt.smb.native_lanman)
  except AttributeError as e:
    pass

  try:
    if pkt.smb.primary_domain <> '0000':
      print('  Primary Domain: %s' % pkt.smb.primary_domain)
  except AttributeError as e:
    pass




def accessingServices (pcapFile,filter):
#  filter = 'smb.cmd == 0x04 || smb.cmd == 0x24 || smb.cmd == 0x25 || smb.cmd == 0x2e || smb.cmd == 0x2f || smb.cmd 0x32 || smb.cmd == 0x71 ||smb.cmd == 0x72 || smb.cmd == 0x73 || smb.cmd == 0x74 || smb.cmd == 0x75 || smb.cmd == 0xa2'
  cap = pyshark.FileCapture(pcapFile, display_filter=filter)
  for pkt in cap:

    try:
      time = pkt.sniff_time
    except AttributeError as e:
      time = 'time - unknown error'
      pass

    try:
      skip = 0
      cmd = int(pkt.smb.cmd)
      if cmd == 43: #0x2b, smb echo, nothing of use at this time, just noisy!
        skip = 1
#      elif cmd == 46: #0x2e   #not sure there is anything in here I'm not getting in the actual create 0xa2
#        skip = 1
    except AttributeError as e:
      pass

    if skip == 0:
      try:
        print('%s -> %s (%s)' % (pkt.ip.src, pkt.ip.dst, time))

        getStatusCode(pkt)

        getShareAccess(pkt)  #need to determine what cmd this is applicable too and only call it on that.  0x2e, a2, 2f,25, 04

        cmd = int(pkt.smb.cmd)
        if cmd == 4: #0x04
          getClose(pkt)
        elif cmd == 16: #0x10   Check directory, seems to be to see if they have a home directory on the server (dc in this case?)
          pass
        elif cmd == 36: #0x24
          getLocking(pkt)
        elif cmd == 37: #0x25
          getTrans(pkt)
        elif cmd == 43: #0x2b, smb echo, nothing of use at this time, just noisy!
          pass
        elif cmd == 45: #0x2d, Extended file open AndX chaining
          getOpenAndX(pkt)
        elif cmd == 46: #0x2e   #not sure there is anything in here I'm not getting in the actual create 0xa2
          getCommRead(pkt)
# look at reads and see if we can tell when they start and finish, if so utilize those 2 out of the "millions"  smb.offset == 0
        elif cmd == 47: #0x2f
          getCommWrite(pkt)
        elif cmd == 50:  #0x32
          getFileInfo(pkt)
        elif cmd == 113: #'0x71':
          getTreeDisconnects(pkt)
        elif cmd == 114: #0x72:
          clientServer(pkt, 'both')
        elif cmd == 115: #0x73
          nativeInfo(pkt)
        elif cmd == 116: #'0x74':
          getLogoffs(pkt)
        elif cmd == 117: #'0x75':
          getTreeConnects(pkt)
        elif cmd == 162: #'0xa2
          getCreateAndX(pkt)
        else:
          print('  Unknown CMD: %s' % cmd)

      except AttributeError as e:
        pass


def test(pcapFile,filter):
  #Determine Client/Server info
  cap = pyshark.FileCapture(pcapFile, display_filter=filter)
  for pkt in cap:
    try:
      cmd = int(pkt.smb.cmd)
      if cmd == 37: #0x25
        getTrans(pkt)

    except AttributeError as e:
      pass

def get_args():
  parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description='Information:\n-Requires thark and pyshark to be installed. \n-Does not like very large pcaps, keep to under 1GB or risk running out of swap space.\n-HIGHLY recommend local system time is set to UTC!', epilog='Example(s): \n python smbParser.py -i=stark-smb.pcap -cs=both -f="(ip.src==10.0.10.100 and ip.dst==10.0.10.101) or (ip.src==10.0.10.101 and ip.dst==10.0.10.102)" \n python smbParser.py -i=stark-smb.pcap -cs=server \n python smbParser.py -i=stark-smb.pcap -n \n python smbParser.py -i=stark-smb.pcap -n -f="ip.dst==10.0.10.102"\n python smbParser.py -i=stark-smb.pcap -fl \n python smbParser.py -i=stark-smb.pcap -fl -f="ip.src==10.0.10.100" \n python smbParser.py -i=stark-smb.pcap \n python smbParser.py -i=stark-smb.pcap -f="ip.dst==10.0.10.101"')
  parser.add_argument('-i', '--input', help='filename to open', required=True)
  parser.add_argument('-f', '--filter', help='display filter to use for raw/json', default='smb', required=False)
#  parser.add_argument('-r', '--raw', help='provide raw output', action='store_true') 
#  parser.add_argument('-j', '--json', help='provide json output', action='store_true')
  parser.add_argument('-cs', '--clientServer', help='provide just client/server info.  Options:  both, client, or server', required=False)
  parser.add_argument('-n', '--native', help='provide native info', action='store_true')
  parser.add_argument('-fl', '--fileList', help='get file list', action='store_true')
  args = vars(parser.parse_args())
  return args

args = get_args()
pcap=args['input']
filter=args['filter']
search=args['clientServer']

print(args)

if args['clientServer']:
  cap = pyshark.FileCapture(pcap, display_filter='smb.cmd == 0x72 && ' + filter)
  for pkt in cap:
    try:
      time = pkt.sniff_time
    except AttributeError as e:
      time = 'time - unknown error'
      pass
    print('Packet Time:  %s' % time)

    clientServer(pkt, search)
elif args['native']:
  cap = pyshark.FileCapture(pcap, display_filter='smb.cmd == 0x73 && ' + filter)
  for pkt in cap:
    try:
      time = pkt.sniff_time
    except AttributeError as e:
      time = 'time - unknown error'
      pass

    try:
      print('%s -> %s (%s)' % (pkt.ip.src, pkt.ip.dst, time))
    except AttributeError as e:
      pass

    nativeInfo(pkt)
elif args['fileList']:
  cap = pyshark.FileCapture(pcap, display_filter='(smb.cmd == 0xa2 || smb.cmd == 0x32 || smb.cmd == 0x04) && ' + filter)
  for pkt in cap:
    try:
      time = pkt.sniff_time
    except AttributeError as e:
      time = 'time - unknown error'
      pass

    try:
      print('%s -> %s (%s)' % (pkt.ip.src, pkt.ip.dst, time))
    except AttributeError as e:
      pass

    getCreateAndX(pkt)
    getFileInfo(pkt)
    getClose(pkt)
else:
  accessingServices(pcap, filter)
#  test(pcap,filter)

