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

    def __init__(self):
        self.rng = secrets.SystemRandom()
        self.configDefaults = {'location': self.PATH_HOME + '/prjremDat'}
        self.config = self.configDefaults
        self.passwords = dict()
        self.psw = b'1234123412341234'
        self.error = 'Unknown error'

    def getSortedKeys(self):
        '''Password keys in a sorted list'''
        return sorted(self.passwords.keys()) 

    def setPassLocation(self, path):
        self.config['location'] = path

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
        if Path(self.PATH_CONF).exists():
            with Path(self.PATH_CONF).open() as f:
                for k,v in json.load(f).items():
                    self.config[k] = v
        else:
            Path(self.PATH_HOME).mkdir(exist_ok=True)

    def saveConf(self):
        with Path(self.PATH_CONF).open(mode='w') as f:
            f.write(json.dumps(self.config))

    def readPass(self):
        '''Open password file and attempt decryption\n
        Returns 0 on success'''
        if not Path(self.config['location']).exists():
            return 1

        with Path(self.config['location']).open(mode='rb') as f:
            bStream = f.read()

        try:
            cipher = AES.new(bytearray(self.psw, self.ENC), AES.MODE_CBC, bStream[:16])
            self.passwords = json.loads(cipher.decrypt(bStream[16:]))
            return 0
        except Exception as e:
            self.error = e

        return 1

    def savePass(self):
        '''Convert passwords to JSON and encrypt with CBC\n
        Use a random IV, prepend it and use trailing 0's as padding'''
        cipher = AES.new(bytearray(self.psw, self.ENC), AES.MODE_CBC, bytearray(self.sequence(16), self.ENC))
        stream = json.dumps(self.passwords)
        stream.join('0' * (32 - (len(stream) % 16)))
        bStream = cipher.encrypt(bytearray(stream, self.ENC))
        with Path(self.config['location']).open(mode='wb') as f:
            f.write(cipher.iv)
            f.write(bStream)

    # Commands
    def make(self, usr, psw=None):
        '''Creates a new password\n
        Returns 0 on success'''
        self.error = 'Arguments may only contain numbers, letters and the special characters: %s' % self.SYMBOLS
        if self.isLegit(usr) is False:
            return 1
        if psw is None:
            psw = self.sequence(16)
        elif self.isLegit(psw) is False:
            return 1
        
        self.passwords[usr] = psw
        return 0

    def retrieve(self, identifier):
        '''Looks up a password by key or number\n
        Returns Tuple with Key and Password or None'''
        if identifier in self.passwords:
            return (identifier, self.passwords[identifier])
        
        try:
            num = int(identifier)
            identifier = self.getSortedKeys()[num]
            return (identifier, self.passwords[identifier])
        except Exception as e:
            self.error = e

        return None



# UI
class PrjRemCMD(cmd.Cmd):
    intro = 'Project Remembrance\'s Commandline Interface'
    prompt = '> '
    file = None

    def emptyline(self):
        self.do_help(None)

    def can_exit(self):
        return True

    def do_exit(self, e):
        '''Write passwords to set location and exit the program'''
        print('Writing to file. Please wait.')
        self.program.savePass()
        return True
    
    do_EOF = do_exit
    do_q = do_exit
    do_quit = do_exit

    def preloop(self):
        '''Read config, prompt for encryption key and decrypt password file'''
        self.program = PrjRem()
        self.program.readConf()
        # self.program.psw = getpass.getpass('Enter password: ')
        if 0 == self.program.readPass():
            self.do_list('')
            print('Loaded %s' % self.program.config['location'])

    def default(self, line):
        '''Try and interpret line as a key to a stored password'''
        self.do_retrieve(line)

    def do_retrieve(self, line):
        '''Try and interpret line as a 'usr' key to retrieve a password 
        \nRetrieve is the default line command.'''
        psw = self.program.retrieve(line)
        if psw is None:
            print(self.program.error)
        else:
            print('%s\n%s' % (psw[0], psw[1]))
            pyperclip.copy(psw[1])

    def do_make(self, arg, psw = None):
        '''make usr [psw]\n
        Creates a new password stored under the "usr" key.\n
        "psw" is optional. If left out a random password is generated.'''
        args = arg.split()
        if len(args) > 0:
            if len(args) > 1:
                psw = args[1]
            if 0 == self.program.make(args[0], psw):
                print('%s made!' % args[0])
                pyperclip.copy(self.program.passwords[args[0]])
            else:
                print(self.program.error)

    def do_gen(self, arg):
        print(self.program.sequence(16))

    def do_info(self, arg):
        print(self.program.config)

    def do_save(self, arg):
        for x in range(0,4):
            self.program.passwords['ent%s' % x] = self.program.sequence(16)

        self.program.savePass()

    def do_read(self, arg):
        self.program.readPass()
        print(self.program.passwords)
    
    def do_list(self, arg):
        ident = 0
        for x in self.program.getSortedKeys():
            print('%s) %s' % (ident, x))
            ident += 1

    def do_check(self, s):
        print(self.program.isLegit(s))

if __name__ == '__main__':
    PrjRemCMD().cmdloop()
