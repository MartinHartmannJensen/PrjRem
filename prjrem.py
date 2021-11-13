import json, cmd, pyperclip, secrets, string, re, getpass, subprocess
from Crypto.Cipher import AES
from Crypto.Protocol import KDF
from pathlib import Path, PureWindowsPath

class PrjRemLegacy:
    def __init__(self):
        self.passwords = dict()
        self.error = 'clean'

    def readVersion2(self, location, psw):
        '''Open password files from version 2.0\n
        Return 0 on success'''
        if psw == '':
            self.error = 'Abort!'
            return 1

        psw = ''.join([psw, '0' * (32 - (len(psw) % 16))])

        if not Path(location).exists():
            return 1

        with Path(location).open(mode='rb') as f:
            es = f.read()

        try:
            cipher = AES.new(bytearray(psw, 'utf_8'), AES.MODE_CBC, es[:16])
            bs = cipher.decrypt(es[16:])
            self.passwords = json.loads(bs.rstrip(b'0'))
            return 0
        except Exception as e:
            self.error = e

        return 1


class PrjRem:
    SYMBOLS = '!@#$/?;:'
    CHAR_SET = '%s%s%s%s' % (SYMBOLS, string.ascii_lowercase, string.digits, string.ascii_uppercase)
    CHAR_SET_LENGTH = len(CHAR_SET) - 1
    CHAR_SET_RE = re.compile('([%s]|[0-9]|[a-z]|[A-Z])+' % SYMBOLS)
    ENC = 'utf_8'
    PATH_HOME = Path.home().as_posix() + '/.prjrem'
    PATH_CONF = PATH_HOME + '/config.json'
    PATH_TEMPFILE = PATH_HOME + '/description'
    DEFAULT_CONFIG = {'location': PATH_HOME + '/prjremDat', 'editor': None}
    STATUS = {'NO-FILE': 0, 'LOCKED': 1, 'UNLOCKED': 2, 'NEW': 3}

    def __init__(self):
        self.rng = secrets.SystemRandom()
        self.config = self.DEFAULT_CONFIG
        self.passwords = dict()
        self.psw = None
        self.error = 'Unknown error'
        self.filestatus = self.STATUS['NO-FILE']

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
            self.filestatus = self.STATUS['NO-FILE']
            return 1

        if ppdir.is_dir():
            self.config['location'] = pp.as_posix()
            if pp.is_file:
                self.filestatus = self.STATUS['NEW']

            return 0

        self.error = 'Not a valid directory.\n%s' % ppdir

    def setPsw(self, psw):
        '''Generate a derived key for encryption. Save it to self.psw'''
        if psw == '':
            self.error = 'Abort!'
            return 1

        self.psw = KDF.scrypt(psw, "takesawhilebutishardtobruteforce", 32, N=2**20, r=8, p=1)
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
            cipher = AES.new(self.psw, AES.MODE_CBC, es[:16])
            bs = cipher.decrypt(es[16:]).decode()
            # Strip padding at end of bytestream before json object marker '}'
            for i in range(len(bs) - 1, 0, -1):
                if(bs[i] == '}'):
                    bs = bs[:i + 1]
                    break

            self.passwords = json.loads(bs)
            self.filestatus = self.STATUS['UNLOCKED']
            return 0
        except Exception as e:
            self.error = e
            self.filestatus = self.STATUS['LOCKED']

        return 1

    def savePass(self):
        '''Convert passwords to JSON and encrypt with CBC\n
        Sequence() is used for random padding. IV is prepended lastly.'''
        iv = bytearray(self.sequence(16), self.ENC)
        cipher = AES.new(self.psw, AES.MODE_CBC, iv)
        stream = bytearray(json.dumps(self.passwords), self.ENC)
        stream = stream + bytearray(self.sequence(16 - (len(stream) % 16)), self.ENC)
        es = cipher.encrypt(stream)
        try:
            with Path(self.config['location']).open(mode='wb') as f:
                f.write(iv)
                f.write(es)
        except Exception as e:
            self.error = e
            return 1

        return 0

    # Commands
    def cmd_make(self, usr, psw=None, desc=None):
        '''Create a new password\n
        Return 0 on success'''
        self.error = 'Arguments may only contain numbers, letters and the special characters: %s' % self.SYMBOLS
        if self.isLegit(usr) is False:
            return 1
        if psw is None:
            psw = self.sequence(16)
        elif self.isLegit(psw) is False:
            return 1
        
        self.passwords[usr] = [psw, desc]
        return 0

    def cmd_retrieve(self, identifier):
        '''Look up a password by key or number\n
        Return None or a tuple with key, password and description'''
        if identifier not in self.passwords:
            try:
                num = int(identifier)
                identifier = self.getSortedKeys()[num]
            except Exception as e:
                self.error = e
                return None

        return (identifier, self.passwords[identifier][0], self.passwords[identifier][1])

    def cmd_describe(self, identifier):
        '''Open a textfile with the designated editor. Command waits for editor to exit\n
        and saves the string to the password description'''
        if self.cmd_retrieve(identifier) is None:
            return 1

        with Path(self.PATH_TEMPFILE).open(mode='w') as f:
            f.write(str(self.passwords[identifier][1]))

        try:
            editor = str(PureWindowsPath(self.config['editor']))
            descfile = str(PureWindowsPath(self.PATH_TEMPFILE))
            subprocess.call([editor, descfile])
        except Exception as e:
            self.error = e
            return 1
        
        with Path(self.PATH_TEMPFILE).open() as f:
            self.passwords[identifier][1] = f.read()

        return 0

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
    prompt = 'PrjRem no-file> '
    file = None

    # The most recent command arguments are split into these 2 lists
    words = list()
    switches = list()

    def setprompt(self):
        stat = ''
        if self.program.filestatus != 2:
            for k,v in self.program.STATUS.items():
                if self.program.filestatus == v:
                    stat = k
        
        self.prompt = '\nPrjRem %s %s> ' % (stat, self.program.config['location'])

    def emptyline(self):
        self.do_help(None)

    def can_exit(self):
        return True

    def preloop(self):
        '''Read config, prompt for encryption key and decrypt password file'''
        self.program = PrjRem()
        self.program.readConf()
        print('\n====\nProject Remembrance\'s Commandline Interface\n====\n')
        self.do_open('')

    def precmd(self, line):
        '''Split arguments into words and switches.'''
        self.words = line.split()
        if len(self.words) > 0:
            del self.words[0]

        self.switches = re.findall('-\w+', line)
        for a in self.switches:
            self.words.remove(a)

        return line

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
            print('Retrieved "%s" and copied password to clipboard.\nDescription:\n--\n%s\n' % (psw[0], psw[2]))
            pyperclip.copy(psw[1])

    def do_openold(self, arg):
        '''
        > openold
        Open version 2 password files.
        Prompt for password and attempt to read the current path.
        '''
        prjl = PrjRemLegacy()
        psw = getpass.getpass('Type password: ')
        if 0 < prjl.readVersion2(self.program.config['location'], psw):
            print('Wrong password. Do "openold" to try again or see "psw" and "loc" to use another file.')
        else:
            self.program.setPsw(psw)
            self.program.passwords = prjl.passwords
            self.program.filestatus = self.program.STATUS['UNLOCKED']
            self.setprompt()
            print('Read successful!\nWARNING: old filepath is still active. Change location if not to overwrite.')

    def do_open(self, arg):
        '''
        > open
        Prompt for password and attempt to read the current path.
        '''
        print('Opening: %s' % self.program.config['location'])
        self.do_psw('')
        if 0 < self.program.readPass():
            print('Wrong password. Do "open" to try again or see "psw" and "loc" to use another file.')
        self.setprompt()

    def do_make(self, arg):
        '''
        > make usr [-m | -manual] [description]+
        Create a new password which is stored under the "usr" key.
        Use the manual switch to type the password instead of generating one.
        Extra arguments will be treated as text to be added to the description.
        To do a longer description use the command "describe".
        '''
        if len(self.words) > 0:
            usr = self.words[0]
            description = ' '.join([str(x) for x in self.words[1:]])
            if '-m' in self.switches or '-manual' in self.switches:
                psw = ''
                while True:
                    psw = getpass.getpass('Enter password: ' )
                    if len(psw.strip()) > 0:
                        break

                if 0 < self.program.cmd_make(usr, psw, description):
                    print(self.program.error)

            else:
                if 0 < self.program.cmd_make(usr, None, description):
                    print(self.program.error)

            print('%s made!' % usr)
            pyperclip.copy(self.program.passwords[usr][0])

    def do_describe(self, arg):
        '''
        > describe usr
        Add description to an existing "usr" key.
        '''
        if len(self.words) > 0:
            if 0 < self.program.cmd_describe(self.words[0]):
                print(self.program.error)

    def do_del(self, arg):
        '''
        > del usr
        Remove stored password by usr key.
        '''
        if len(self.words) > 0:
            if 0 == self.program.cmd_delete(self.words[0]):
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
                self.setprompt()
                self.program.saveConf()
            else:
                print(self.program.error)

    def do_exit(self, e):
        '''
        > exit | quit | q | EOF [-n | -nosave]
        Write passwords to current location and exit the program.
        Pass the -nosave switch to exit without saving current session to password file.
        '''
        self.program.saveConf()
        if '-n' in self.switches or '-nosave' in self.switches:
            return True

        if len(self.program.passwords) > 0 and self.program.filestatus > 1:
            print('Writing to file. Exiting.\n')
            if 0 < self.program.savePass():
                print(self.program.error)

            return True
        
        print('Cannot exit. No password file chosen.\nTo force an exit, use the -nosave switch. Details under "help exit"')

    do_EOF = do_exit
    do_q = do_exit
    do_quit = do_exit


if __name__ == '__main__':
    PrjRemCMD().cmdloop()
