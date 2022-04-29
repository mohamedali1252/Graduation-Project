from itertools import count
from pickle import TRUE
from zope.interface import Interface, implements
from twisted.application import internet
from twisted.protocols import basic, policies
from twisted.internet import protocol, reactor, defer
from twisted.python import log
from twisted.conch.insults.insults import TerminalProtocol
from re import match
from twisted.internet import task
import socket
#from common import PotFactory
from time import strftime
import os
import time
import pyshark
import datetime




UP_KEY = '\x1b[A'.encode()
DOWN_KEY = '\x1b[B'.encode()
RIGHT_KEY = '\x1b[C'.encode()
LEFT_KEY = '\x1b[D'.encode()
BACK_KEY = '\x7f'.encode()



WELCOME_MSG                   = b'220'
GOODBYE_MSG                   = b'221'

USER_OK_NEED_PASS             = b'331'
PLEASE_SPECIFY_USER_NAME      = b'5'

PLEASE_LOGIN                  = b'53'
UNKNOWN_COMMAND               = b'500'
LOGIN_WITH_USER_FIRST         = b'03'
LOGIN_FAIL                    = b'530'
LOGIN_SUCCEED                 = b'230'
REQ_ACTN_NOT_TAKEN            = b'550'
HELP_MSG                      = b'214'  
ASCII_COMMAND                 = b'2'
BINARY_COMMAND                = b'200'
CWD_COMMAND                   = b'250'
LS_COMMAND                    = b'20'
PLEASE_SPECIFY_PASS           = b'503'
LOGIN_ANONYMOUS_SUCCEED       = b'3'
PLEASE_SPECIFY_DIR            = b'9'
PLEASE_SPECIFY_LocalFile_Path = b'77'
PUT_COMMAND                  = b'88'
SU_COMMAND                   = b'89'
SU_ERROR                     = b'787'
NEED_ROOT                    = b'3433'

RESPONSE = {
    WELCOME_MSG:              b'Connected to 192.168.56.1\n220- - - Welcome to ftp - - -',

    GOODBYE_MSG:              b'221 Goodbye.',

    USER_OK_NEED_PASS:        b'331 Please specify the password.',

    PLEASE_LOGIN:             b'530 Please login with USER and PASS.',
    UNKNOWN_COMMAND:          b'500 Unknown command.',
    LOGIN_WITH_USER_FIRST:    b'503 Login with USER first.',
    LOGIN_FAIL:               b'530 Login incorrect.',
    LOGIN_SUCCEED:            b'230 User logged in\nRemote System type is UNIX\nusing binary mode to transfer files',
    LOGIN_ANONYMOUS_SUCCEED:  b'230 User anonymous logged in\nRemote System type is UNIX\nusing binary mode to transfer files',
    REQ_ACTN_NOT_TAKEN:       b'550 Requested action not taken: %s',
    HELP_MSG:                 b'214-The following commands are recognized.\nUSER            PASS            CWD\nPWD             QUIT            BYE             \nLS              ASCII           BINARY\nPUT             SITE CHMOD\n214 Help Ok.'
    ,
    ASCII_COMMAND:               b'200 Type set to ASCII',
    BINARY_COMMAND:              b'200 Type set to BINARY', 
    CWD_COMMAND:                 b'250 CWD command successful.',  
    LS_COMMAND:                  b"""200 PORT Command successful.
150 opening ASCII mode data connection for file list
r--   1 web site      18166 Jun  8 19:12 'test2.docm'
dr--  5 web site      1024 Feb  2 04:04  .
dr--  7 web site      1894 Jan  2 03:29  ..
 """,
    PLEASE_SPECIFY_USER_NAME:     b'503 Please Specify User Name',
    PLEASE_SPECIFY_PASS:          b'503 Please Specify the password',
    PLEASE_SPECIFY_DIR :          b'503 Please Specify the dirctory',
    PLEASE_SPECIFY_LocalFile_Path:b'503 Please Specify Local File Path',
    PUT_COMMAND:                  b'200 PORT command successful.',
    SU_COMMAND:                   b'230 root logged in',
    SU_ERROR:                     b'530 root password incorrect.',    
    NEED_ROOT:                    b'Changing Permissions need Root Privileges'              

   
}




class FTPpot(basic.LineOnlyReceiver, policies.TimeoutMixin):

    disconnected = False
    isanonymous  = 0
    isuser       = 0
    userdone     = 0
    passdone     = 0
    loggedin     = 0
    isroot       = 0
    su_entered   = 0
    first_con    = 1
    con_id       = ''
    con_list     = [] 

    dir_files = {                             #dictionary of dir->files list

     'ftpdefaultdir': 
     ['200 PORT Command successful.\n',
'150 opening ASCII mode data connection for file list\n',
'r--   1 web site      18166 Jun  8 19:12   test2.docm\n',
'dr--  7 web site      1894  Jan  2 03:29   dir_1\n',
'dr--  7 web site      1894  Jan  2 03:29   dir_2\n',
'dr--  5 web site      1024  Feb  2 04:04   .\n',
'dr--  7 web site      1894  Jan  2 03:29   ..\n'],
'dir_1':
 ['200 PORT Command successful.\n',
'150 opening ASCII mode data connection for file list\n',
'r--   1 web site      18166 Jun  8 19:12   test.docm\n',
'dr--  5 web site      1024  Feb  2 04:04   .\n',
'dr--  7 web site      1894  Jan  2 03:29   ..\n'],
'dir_2':
['200 PORT Command successful.\n',
'150 opening ASCII mode data connection for file list\n',
'r--   1 web site      18166 Jun   8 19:12   test.pdf\n',
'dr--  5 web site      1024  Feb   2 04:04   .\n',
'dr--  7 web site      1894  Jan   2 03:29   ..\n'],

    }   
    #Features related vars          

    current_dir       =     'ftpdefaultdir'                            #cuurent working Dir                                                                     #Feature Extraction Table (1)
    available_dir     =   ['ftpdefaultdir' ,'dir_1','dir_2']
    con_start_time    =   0
    con_end_time      =   0
    land              =   0                                            #traffic features Table (3)
    count             =   0                                            #table (2)
    num_failed_logins =   0                                            #num_failed_logins per single connection 
    num_created_files =   0
    root_shell        =   0                                            # 5- Root_shell: 1 if root shell is obtained; 0 otherwise.
    su_attempted      =   0                                            # 6- Su_attempted: 1 if “su root” command attempted or used; 0 otherwise.
    num_root          =   0                                            # 7- Num_root: number of operations performed as a root in the connection.
    num_access_files  =   0                                            # 8- Num_access_files: Number of operations on access control files .
    num_shells        =   1
    num_file_creations =  0                                            #second phase ISA
    num_outbound_cmds   =  0
    is_hot_login       =  0
    is_guest_login     =  0
    hot                =  0                                            #Num HOT indicators such as: entering a system directory, creating programs and executing programs.
    num_compromised_files = 0 
    ftplog =   ftplog = open("ftplog.txt", "w")                                       #second phase ISA
   
    def sendLine(self, msg):
      basic.LineOnlyReceiver.sendLine(self, msg)
      
      

    def reply(self, key,sec_line):
        #msg = RESPONSE[key] % args
          
          msg = RESPONSE[key]
          self.sendLine(msg)
          if sec_line == 1:
              self.transport.write(b'ftp> ')
          
        
    

    def connectionMade(self):
        self.count = self.count + 1
 
        self.con_start_time = time.time()
        self.con_id += str(self.con_start_time)
        self.con_id += ' '
        self.con_id += self.transport.getHost().host
        self.con_id += ' '
        self.con_id += '23'
        self.con_id += ' '
        self.con_id+= self.transport.getPeer().host
        self.con_id += ' '
        self.con_id +=str(self.transport.getPeer().port)
        #clear the con_list
        self.con_list.clear()
        self.con_list.append(self.con_id)

        if self.first_con == 1:
            self.first_con = 0
      
        self.reply(WELCOME_MSG,0)
       
        #create a log file
        if self.first_con == 0:
            self.ftplog = open("ftplog.txt", "a")

        	
		
        

       


    def connectionLost(self, reason):
        # log.msg(reason)
        #F1: Duration
        duration =   time.time() - self.con_start_time
        log.msg('duration=%s'% duration)
        log.msg(self.transport.getPeer().host)

        #content related features
        self.con_list.append(',')
        self.con_list.append(self.hot)
        self.con_list.append(',')
        self.con_list.append(self.num_failed_logins)
        self.con_list.append(',')
        self.con_list.append(self.loggedin)
        self.con_list.append(',')
        self.con_list.append(self.num_compromised_files)
        self.con_list.append(',')
        self.con_list.append(self.root_shell)
        self.con_list.append(',')
        self.con_list.append(self.su_attempted)
        self.con_list.append(',')
        self.con_list.append(self.num_root)
        self.con_list.append(',')
        self.con_list.append(self.num_file_creations)
        self.con_list.append(',')
        self.con_list.append(self.num_shells)
        self.con_list.append(',')
        self.con_list.append(self.num_access_files)
        self.con_list.append(',')
        self.con_list.append(self.num_outbound_cmds)
        self.con_list.append(',')
        self.con_list.append(self.is_hot_login)
        self.con_list.append(',')
        self.con_list.append(self.is_guest_login)
        self.con_list.append('\n')
        


        for i in range(0,len(self.con_list)):
            if i > 0:
                self.ftplog.write(str(self.con_list[i]))
                print(str(self.con_list[i]))
            else:
                self.ftplog.write(self.con_list[i])

          
        self.ftplog.close()


        

        
        self.setTimeout(None)
        
        self.transport = None

    def timeoutConnection(self):
        line = "ConnectionTimeout: %s : %s : %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host, self.username.decode("utf8"),self.password.decode("utf8"))
        #log.msg(line)
        self.transport.loseConnection()

    def lineReceived(self, line):
        self.resetTimeout()

        def processFailed(err):
            #if err.check(FTPCmdError):
            #    self.sendLine(err.value.response())
            #else:
            #log.msg("Unexpected FTP error")
            log.err(err)

        def processSucceeded(result):
            if isinstance(result, tuple):
                self.reply(*result,1)
            elif result is not None:
                self.reply(result,1)

        d = defer.maybeDeferred(self.processCommand, line)
        d.addCallbacks(processSucceeded, processFailed)
        d.addErrback(log.err)

    def processCommand(self, line):
        if not line: return
        cmd, args = match(b'(\S+)\s*(.*)$', line.rstrip()).groups()
        cmd = cmd.upper()
        if self.loggedin == 0:
         if cmd == b'USER':
             if  args == b'':
                self.userdone = 0
                self.passdone = 0
                print(args)
                return PLEASE_SPECIFY_USER_NAME

             else:
                 self.userdone =1
                 self.passdone=0
                 print('else')
                 return self.ftp_USER(args)
            
                 

         elif cmd == b'PASS':
                if  args == b'':
                  self.passdone = 0
                  return PLEASE_SPECIFY_PASS
              
                elif  self.userdone == 0:
                 
                   self.passdone=0
                   return LOGIN_WITH_USER_FIRST
                else :
                   self.passdone=1
                   self.userdone=1
                   return self.ftp_PASS(args)

         elif cmd == b'BYE':
              return self.ftp_QUIT()

         elif cmd == b'QUIT':
              return self.ftp_QUIT()
         if cmd == b'HELP':
              return self.ftp_HELP()
         else:
             return LOGIN_WITH_USER_FIRST


      #commands that need credintials
        elif self.loggedin == 1:
            if cmd == b'HELP':
              if self.root_shell == 1:
                  self.num_root +=1
              return self.ftp_HELP()

            elif cmd == b'ASCII':
              if self.root_shell == 1:
                  self.num_root +=1
              return self.ftp_ASCII()

            elif cmd == b'BINARY':
              if self.root_shell == 1:
                  self.num_root +=1
              return self.ftp_BINARY()

            elif cmd == b'BYE':
              if self.root_shell == 1:
                  self.num_root +=1
              return self.ftp_QUIT()

            elif cmd == b'QUIT':
              if self.root_shell == 1:
                  self.num_root +=1
              return self.ftp_QUIT()

            elif cmd == b'LS':
              if self.root_shell == 1:
                  self.num_root +=1
              return self.ftp_LS()

            elif cmd == b'PWD':
              if self.root_shell == 1:
                  self.num_root +=1
              return self.ftp_PWD()

            elif cmd == b'CWD':
                if self.root_shell == 1:
                  self.num_root +=1
                if args == b'':
                    return PLEASE_SPECIFY_DIR
                else:
                   return self.ftp_CWD(args)
            elif cmd == b'PUT':
                if self.root_shell == 1:
                  self.num_root +=1
                if args == b'':
                    return PLEASE_SPECIFY_LocalFile_Path
                else:
                    return self.ftp_PUT(args)

            elif cmd == b'SU':
                self.transport.write(b'Password: ')
                self.su_entered = 1
                self.su_attempted =1
                
                
                
            elif cmd == b'ROOT' and  self.su_entered == 1:
                self.root_shell = 1
                self.num_root +=1
                self.is_hot_login = 1

                return self.ftp_SU()

            elif cmd == b'SITE CHMOD':
                if self.root_shell == 1:
                  self.num_root +=1
                if self.root_shell == 0:
                    self.num_access_files += 1
                    return NEED_ROOT
                else:
                    return self.ftp_CHMOD()


            else:
              #return UNKNOWN_COMMAND
              self.sendLine(b'500 Unknown command.')
              log.msg(cmd)
              log.msg(args)
              self.transport.write(b'ftp> ')



    def ftp_USER(self, username):
        self.username = username
        line = "USER : %s : %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().port, self.username.decode("utf8"))
        #log.msg(line)
        if self.username.decode("utf8") == 'anonymous':
             self.isanonymous = 1
             self.is_guest_login = 1
                
        else:
            self.isanonymous = 0

        if self.username.decode("utf8") == 'admin':
            self.isuser = 1
                  
        else:
            self.isuser = 0

        self.reply(USER_OK_NEED_PASS,0)

    def ftp_PASS(self, password):
         line = "PASS : %s : %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host, password.decode("utf8"))
         #log.msg(line)
         if bool(self.isanonymous) :
            self.loggedin = 1
            
            #return LOGIN_ANONYMOUS_SUCCEED
            #self.sendLine(b'230 User anonymous logged in\nRemote System type is UNIX\nusing binary mode to transfer files')
            #self.transport.write(b'ftp> ')
            self.reply(LOGIN_ANONYMOUS_SUCCEED,1)
         elif bool(self.isuser) and password.decode("utf8") == 'adminadmin':
             self.loggedin = 1
             
             #return LOGIN_SUCCEED
             self.reply(LOGIN_SUCCEED,1)
             #self.sendLine( b'230 User logged in\nRemote System type is UNIX\nusing binary mode to transfer files')
             #self.transport.write(b'ftp> ')
         else:
             self.loggedin = 0
             del self.username
             self.num_failed_logins += 1 
             #return LOGIN_FAIL
             self.reply(LOGIN_FAIL,0)


    def ftp_FEAT(self, line):
        line = "FEAT: %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host)
        #log.msg(line)
        self.sendLine(b'211-Features:')
        for i in b'EPRT,EPSV,MDTM,PASV,REST STREAM,SIZE,TVFS,UTF8'.split(b','):
            self.sendLine(b' %s' % i)
        self.sendLine(b'211 End')
    
    def ftp_HELP(self):
       
        #log.msg("HELP: %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host))
        
        if self.loggedin == 1:
            self.reply(HELP_MSG,1)
        else:
            self.reply(HELP_MSG,0)

        

        

    def ftp_QUIT(self):
        line = "Quit: %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host)
        log.msg(line)
        self.reply(GOODBYE_MSG,0)
        self.transport.loseConnection()
        self.disconnected = True

    def ftp_ASCII(self):
        line = "ASCII : %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host)
        #log.msg(line)
        self.reply(ASCII_COMMAND,1)

    def ftp_BINARY(self):
        line = "BINARY : %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host)
        #log.msg(line)
        self.reply(BINARY_COMMAND,1)
    def ftp_LS(self):
        line = "LS : %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host)
        #log.msg(line)
        reply = ''
        for f in  self.dir_files[self.current_dir]:
            reply += f
        basic.LineOnlyReceiver.sendLine(self, reply.encode('UTF-8')+b'\r')
        self.transport.write(b'ftp> ')
      
    
    def ftp_PWD(self):
        line = "PWD : %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host)
        #log.msg(line)
        reply = '257/' + self.current_dir + ' is the current directory.'
        self.sendLine(reply.encode('UTF-8'))
        self.transport.write(b'ftp> ')

    def ftp_CWD(self,dir):
        line = "CWD : %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host)
        #log.msg(line)
        #log.msg(dir)
       
        if self.current_dir in self.available_dir:
             self.current_dir = dir.decode()
             self.reply(CWD_COMMAND,1)
        else:
            reply = '550 No Such File or Directory'
            self.sendLine(reply.encode('UTF-8'))
            self.transport.write(b'ftp> ')

        

    def ftp_PUT(self,args):
        self.num_created_files +=1
        reply = ''
        if ' ' in args.decode():  
            l = args.split()     
            reply = 'rw-   1 web site ' +'     1203  '+ str(datetime.datetime.now().strftime("%b  %d %H:%M  ")) +l+ '\n'
         

        else :
            reply = 'rw-   1 web site ' +'     1203  '+ str(datetime.datetime.now().strftime("%b  %d %H:%M  "))  + args.decode() + '\n'

  
        self.dir_files[self.current_dir].append(reply)
        self.reply(PUT_COMMAND,1)

    
    def ftp_SU(self):
        self.num_root +=1
    

        hotlist = ['root','admin','su root']
        self.reply(SU_COMMAND,1)
        """
        if args.decode() in hotlist:
            self.root_shell = 1
            self.reply(SU_COMMAND,1)
        else:
            self.root_shell = 0
            self.reply(SU_ERROR,1)
        """
    def ftp_CHMOD(self):
        self.num_access_files += 1

      


    

        

    
 

class ftpFactory(protocol.ServerFactory):
    def buildProtocol(self, addr) :
        return FTPpot()








log.startLogging(open('ftp.log','w'))
reactor.listenTCP(22,ftpFactory())




reactor.run()
