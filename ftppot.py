from pickle import TRUE
from zope.interface import Interface, implements
from twisted.application import internet
from twisted.protocols import basic, policies
from twisted.internet import protocol, reactor, defer
from twisted.python import log
from re import match
#from common import PotFactory
from time import strftime
import os
import time


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
PWD_COMMAND                   = b'257'
LS_COMMAND                    = b'20'
PLEASE_SPECIFY_PASS           = b'503'
LOGIN_ANONYMOUS_SUCCEED       = b'3'
PLEASE_SPECIFY_DIR            = b'9'

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
    HELP_MSG:                 b'214-The following commands are recognized.\nUSER            PASS            CWD\nPWD             QUIT            BYE             \nLS              ASCII           BINARY\n214 Help Ok.'
    ,
    ASCII_COMMAND:               b'200 Type set to ASCII',
    BINARY_COMMAND:              b'200 Type set to BINARY', 
    CWD_COMMAND:                 b'250 CWD command successful.',  
    PWD_COMMAND:                 b'257 "/ftpdefaultdir" is current directory.',
    LS_COMMAND:                  b"""200 PORT Command successful.
150 opening ASCII mode data connection for file list
r--   1 web site      18166 Jun  8 19:12 'test2.docm'
dr--  5 web site      1024 Feb  2 04:04  .
dr--  7 web site      1894 Jan  2 03:29  ..
 """,
    PLEASE_SPECIFY_USER_NAME:     b'503 Please Specify User Name',
    PLEASE_SPECIFY_PASS:          b'503 Please Specify the password',
    PLEASE_SPECIFY_DIR :          b'503 Please Specify the dirctory',
   
}

class FTPpot(basic.LineOnlyReceiver, policies.TimeoutMixin):

    delimiter = b'\n'
    disconnected = False
    isanonymous = 0
    isadmin = 0
    userdone = 0
    passdone = 0
    loggedin = 0
    #Feature Extraction
    con_start_time = 0
    con_end_time = 0

    ''' So that FTP clients that use '\n' instead of '\r\n'
        receive responses anyway '''
    def sendLine(self, msg):
      basic.LineOnlyReceiver.sendLine(self, msg+b'\r')
      
      

    def reply(self, key):
        #msg = RESPONSE[key] % args
        msg = RESPONSE[key]
        self.sendLine(msg)

    def connectionMade(self):
        log.msg('connection made')
        log.msg('con_start_time')
        self.con_start_time = time.time()
        log.msg(time.time())
         

        line = "COMMAND : TIME : IP : PARAMS"
        log.msg(line)
        self.reply(WELCOME_MSG)
    def connectionLost(self, reason):
        log.msg(reason)
        duration =   time.time() - self.con_start_time
        log.msg('duration=%s'% duration)
        
        self.setTimeout(None)
        
        self.transport = None

    def timeoutConnection(self):
        line = "ConnectionTimeout: %s : %s : %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host, self.username.decode("utf8"),self.password.decode("utf8"))
        log.msg(line)
        self.transport.loseConnection()

    def lineReceived(self, line):
        self.resetTimeout()

        def processFailed(err):
            #if err.check(FTPCmdError):
            #    self.sendLine(err.value.response())
            #else:
            log.msg("Unexpected FTP error")
            log.err(err)

        def processSucceeded(result):
            if isinstance(result, tuple):
                self.reply(*result)
            elif result is not None:
                self.reply(result)

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
              return self.ftp_HELP()

            elif cmd == b'ASCII':
              return self.ftp_ASCII()

            elif cmd == b'BINARY':
              return self.ftp_BINARY()

            elif cmd == b'BYE':
              return self.ftp_QUIT()

            elif cmd == b'QUIT':
              return self.ftp_QUIT()

            elif cmd == b'LS':
              return self.ftp_LS()

            elif cmd == b'PWD':
              return self.ftp_PWD()

            elif cmd == b'CWD':
                if args == b'':
                    return PLEASE_SPECIFY_DIR
                else:
                   return self.ftp_CWD()
            else:
              return UNKNOWN_COMMAND



    def ftp_USER(self, username):
        self.username = username
        line = "USER : %s : %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().port, self.username.decode("utf8"))
        log.msg(line)
        if self.username.decode("utf8") == 'anonymous':
             self.isanonymous = 1
                
        else:
            self.isanonymous = 0

        if self.username.decode("utf8") == 'admin':
            self.isadmin = 1
                  
        else:
            self.isadmin = 0

        return USER_OK_NEED_PASS

    def ftp_PASS(self, password):
         line = "PASS : %s : %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host, password.decode("utf8"))
         log.msg(line)
         if bool(self.isanonymous) :
            self.loggedin = 1
            return LOGIN_ANONYMOUS_SUCCEED
         elif bool(self.isadmin) and password.decode("utf8") == 'adminadmin':
             self.loggedin = 1
             return LOGIN_SUCCEED
         else:
             self.loggedin = 0
             del self.username
             return LOGIN_FAIL


    def ftp_FEAT(self, line):
        line = "FEAT: %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host)
        log.msg(line)
        self.sendLine(b'211-Features:')
        for i in b'EPRT,EPSV,MDTM,PASV,REST STREAM,SIZE,TVFS,UTF8'.split(b','):
            self.sendLine(b' %s' % i)
        self.sendLine(b'211 End')
    
    def ftp_HELP(self):
       
        log.msg("HELP: %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host))
        self.reply(HELP_MSG)

    def ftp_QUIT(self):
        line = "Quit: %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host)
        log.msg(line)
        self.reply(GOODBYE_MSG)
        self.transport.loseConnection()
        self.disconnected = True

    def ftp_ASCII(self):
        line = "ASCII : %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host)
        log.msg(line)
        self.reply(ASCII_COMMAND)

    def ftp_BINARY(self):
        line = "BINARY : %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host)
        log.msg(line)
        self.reply(BINARY_COMMAND)
    def ftp_LS(self):
        line = "LS : %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host)
        log.msg(line)
        self.reply(LS_COMMAND)
    
    def ftp_PWD(self):
        line = "PWD : %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host)
        log.msg(line)
        self.reply(PWD_COMMAND)

    def ftp_CWD(self):
        line = "CWD : %s : %s\n" % (strftime('%F %T'), self.transport.getPeer().host)
        log.msg(line)
        self.reply(CWD_COMMAND)

class FTPCmdError(Exception):
    """
    Generic exception for FTP commands.
    """
    def __init__(self, *msg):
        Exception.__init__(self, *msg)
        self.errorMessage = msg

    def response(self):
        """
        Generate a FTP response message for this error.
        """
        return RESPONSE[self.errorCode] % self.errorMessage

class ftpFactory(protocol.ServerFactory):
    def buildProtocol(self, addr) :
        return FTPpot()
log.startLogging(open('ftp.log','w'))
reactor.listenTCP(21,ftpFactory())
reactor.run()
