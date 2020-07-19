import json, cmd, pyperclip, secrets, string, re, getpass
from Crypto.Cipher import AES
from pathlib import Path


class PrjRem:
    SYMBOLS = '!@#$/?;:'
    CHAR_SET = '%s%s%s%s' % (SYMBOLS, string.ascii_lowercase, string.digits, string.ascii_uppercase)
    CHAR_SET_LENGTH = len(CHAR_SET) - 1
    CHAR_SET_RE = re.compile('([%s]|[0-9]|[a-z]|[A-Z])+' % SYMBOLS)
    ENC = 'utf_8'
    PATH_HOME = Path.home().as_posix() + '/.prjrem'
    PATH_CONF = PATH_HOME + '/config'
    DEFAULT_CONFIG = {'location': PATH_HOME + '/prjremDat'}

    def __init__(self):
        self.rng = secrets.SystemRandom()
        self.config = self.DEFAULT_CONFIG
        self.passwords = dict()
        self.psw = '0000000000000000'
        self.error = 'Unknown error'

    def getSortedKeys(self):
        '''Password keys in a sorted list'''
        return sorted(self.passwords.keys()) 

    def setPassLocation(self, path):
        '''Check if path is valid before committing to the configuration'''
        try:
            pp = Path(path)
            ppdir = pp.parent
            ppdir.resolve()
        except Exception as e:
            self.error = e
            return 1

        if ppdir.is_dir():
            self.config['location'] = pp.as_posix()
            return 0

        self.error = 'Not a valid directory.\n%s' % ppdir

    def setPsw(self, psw):
        '''Set a password for the context. Also pad it'''
        if psw == '':
            self.error = 'Abort!'
            return 1

        self.psw = ''.join([psw, '0' * (32 - (len(psw) % 16))])
        return 0

    def sequence(self, length):
        '''Generate sequence of randomized characters'''
        seqlist = [self.CHAR_SET[self.rng.randint(0, self.CHAR_SET_LENGTH)] for x in range(0, length)]
        return ''.join(seqlist)

    def isLegit(self, string):
        if self.CHAR_SET_RE.fullmatch(string) is None:
            return False
        return True

    # Interop
    def readConf(self):
        '''Read config file or create the home folder'''
        if Path(self.PATH_CONF).exists():
            with Path(self.PATH_CONF).open() as f:
                for k,v in json.load(f).items():
                    self.config[k] = v
        else:
            Path(self.PATH_HOME).mkdir(exist_ok=True)

    def saveConf(self):
        '''Dump dict to JSON file'''
        with Path(self.PATH_CONF).open(mode='w') as f:
            f.write(json.dumps(self.config))

    def readPass(self):
        '''Open password file and attempt decryption\n
        Return 0 on success'''
        if not Path(self.config['location']).exists():
            return 1

        with Path(self.config['location']).open(mode='rb') as f:
            es = f.read()

        try:
            cipher = AES.new(bytearray(self.psw, self.ENC), AES.MODE_CBC, es[:16])
            bs = cipher.decrypt(es[16:])
            self.passwords = json.loads(bs.rstrip(b'0'))
            return 0
        except Exception as e:
            self.error = e

        return 1

    def savePass(self):
        '''Convert passwords to JSON and encrypt with CBC\n
        Use a random IV, prepend it and use trailing 0's as padding'''
        iv = bytearray(self.sequence(16), self.ENC)
        cipher = AES.new(bytearray(self.psw, self.ENC), AES.MODE_CBC, iv)
        stream = json.dumps(self.passwords)
        stream = ''.join([stream, '0' * (32 - (len(stream) % 16))])
        es = cipher.encrypt(bytearray(stream, self.ENC))
        try:
            with Path(self.config['location']).open(mode='wb') as f:
                f.write(iv)
                f.write(es)
        except Exception as e:
            self.error = e
            return 1

        return 0

    # Commands
    def cmd_make(self, usr, psw=None):
        '''Create a new password\n
        Return 0 on success'''
        self.error = 'Arguments may only contain numbers, letters and the special characters: %s' % self.SYMBOLS
        if self.isLegit(usr) is False:
            return 1
        if psw is None:
            psw = self.sequence(16)
        elif self.isLegit(psw) is False:
            return 1
        
        self.passwords[usr] = psw
        return 0

    def cmd_retrieve(self, identifier):
        '''Look up a password by key or number\n
        Return None or a tuple with key and password'''
        if identifier in self.passwords:
            return (identifier, self.passwords[identifier])

        try:
            num = int(identifier)
            identifier = self.getSortedKeys()[num]
            return (identifier, self.passwords[identifier])
        except Exception as e:
            self.error = e

        return None

    def cmd_delete(self, usr):
        '''Delete password'''
        if usr in self.passwords:
            del self.passwords[usr]
            return 0

        return 1

    def cmd_listToPrint(self):
        '''Formatted string with newlines for each sorted key'''
        return ''.join(['%s) %s\n' % (idx, key) for idx, key in enumerate(self.getSortedKeys())]) 


# UI
class PrjRemCMD(cmd.Cmd):
    intro = '====\nProject Remembrance\'s Commandline Interface\n===='
    prompt = 'PrjRem no-file> '
    file = None

    def emptyline(self):
        self.do_help(None)

    def can_exit(self):
        return True

    def preloop(self):
        '''Read config, prompt for encryption key and decrypt password file'''
        self.program = PrjRem()
        self.program.readConf()
        self.prompt = 'PrjRem %s> ' % self.program.config['location']
        print('Opening: %s' % self.program.config['location'])
        self.do_open('')

    def default(self, line):
        '''Try and interpret line as a key to a stored password'''
        self.do_retrieve(line)

    def do_retrieve(self, line):
        '''
        > retrieve identifier
        Get stored password. "Identifier" can either be a "usr" key or a number
        from the "list" command.
        This is the default line command. "Retrieve" can be excluded.
        '''
        psw = self.program.cmd_retrieve(line)
        if psw is None:
            print(self.program.error)
        else:
            print('%s\n%s' % (psw[0], psw[1]))
            pyperclip.copy(psw[1])

    def do_open(self, arg):
        '''
        > open
        Prompt for password and attempt to read the current path.
        '''
        self.do_psw('')
        if 0 == self.program.readPass():
            print('Listing passwords\n')
            self.do_list('')
        else:
            print('Wrong password. Do "open" to try again or see "psw" and "loc" to use another file.')

    def do_make(self, arg, psw = None):
        '''
        > make usr [psw]
        Create a new password which is stored under the "usr" key.
        "psw" is optional. If left out a random password is generated.
        '''
        args = arg.split()
        if len(args) > 0:
            if len(args) > 1:
                psw = args[1]
            if 0 == self.program.cmd_make(args[0], psw):
                print('%s made!' % args[0])
                pyperclip.copy(self.program.passwords[args[0]])
            else:
                print(self.program.error)

    def do_del(self, arg):
        '''
        > del usr
        Remove stored password by usr key.
        '''
        args = arg.split()
        if len(args) > 0:
            if 0 == self.program.cmd_delete(args[0]):
                print('Deleted')
            else:
                print('Key not found')

    def do_list(self, arg):
        '''
        > list
        List all "usr" keys in a sorted print.
        '''
        print(self.program.cmd_listToPrint())

    def do_psw(self, arg):
        '''
        > psw
        Enter a new password. This is the encryption key and is not stored anywhere.
        It is used for the current context only and applies on the next write.
        Remember well.
        '''
        if 0 < self.program.setPsw(getpass.getpass('Enter password: ')):
            print(self.program.error)

    def do_loc(self, arg):
        '''
        > loc path
        Changes password file location.
        '''
        if len(arg) > 0:
            if 0 == self.program.setPassLocation(arg):
                self.prompt = 'PrjRem %s> ' % self.program.config['location']
                self.program.saveConf()
            else:
                print(self.program.error)

    def do_exit(self, e):
        '''
        Write passwords to current location and exit the program.
        '''
        if len(self.program.passwords) > 0:
            print('Writing to file. Please wait.')
            if 0 < self.program.savePass():
                print(self.program.error)
            else:
                return True

    do_EOF = do_exit
    do_q = do_exit
    do_quit = do_exit


if __name__ == '__main__':
    PrjRemCMD().cmdloop()
