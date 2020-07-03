import json, cmd, pyperclip, secrets, string
from Crypto.Cipher import AES
from pathlib import Path


class PrjRem:
    CHAR_SET = '!@#$%s%s%s' % (string.ascii_lowercase, string.digits, string.ascii_uppercase)
    CHAR_SET_LENGTH = len(CHAR_SET) - 1
    PATH_HOME = Path.home().as_posix() + '/.prjrem'
    PATH_CONF = PATH_HOME + '/config'
    PSW = b'1234123412341234'

    def __init__(self):
        self.rng = secrets.SystemRandom()
        self.configDefaults = {'location': self.PATH_HOME + '/prjremDat'}
        self.config = self.configDefaults
        self.passwords = dict()


    def getSortedKeys(self):
        '''Password keys in a sorted list'''
        return sorted(self.passwords.keys) 

    def setPassLocation(self, path):
        self.config['location'] = path

    def sequence(self, length):
        '''Generate sequence of randomized characters'''
        seqlist = [self.CHAR_SET[self.rng.randint(0, self.CHAR_SET_LENGTH)] for x in range(0, length)]
        return ''.join(seqlist)


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
        '''Open password file and attempt decryption'''
        if not Path(self.config['location']).exists():
            return 1

        with Path(self.config['location']).open(mode='rb') as f:
            bStream = f.read()

        try:
            cipher = AES.new(self.PSW, AES.MODE_CBC, bStream[:16])
            self.passwords = json.loads(cipher.decrypt(bStream[16:]))
            return 0
        except Exception as e:
            self.error = e

        return 1

    def savePass(self):
        '''Convert passwords to JSON and encrypt with CBC\n
        Use a random IV, prepend it and use trailing 0's as padding'''
        cipher = AES.new(self.PSW, AES.MODE_CBC, bytearray(self.sequence(16), 'utf_8'))
        stream = json.dumps(self.passwords)
        stream.join('0' * (32 - (len(stream) % 16)))
        bStream = cipher.encrypt(bytearray(stream, 'utf_8'))
        with Path(self.config['location']).open(mode='wb') as f:
            f.write(cipher.iv)
            f.write(bStream)

    # Commands
    def make(self, usr, psw=None):
        '''Creates a new password'''
        if psw is None:
            psw = self.sequence(16)
        
        self.passwords[usr] = psw

    def retrieve(self, identifier):
        '''Looks up a password by key or number'''
        if identifier in self.passwords:
            return self.passwords[identifier]
        
        try:
            num = int(identifier)
            return self.passwords[self.getSortedKeys()[num]]
        except Exception as e:
            self.error = e

        return None



# UI
class PrjRemCMD(cmd.Cmd):
    intro = 'Project Remembrance\'s Commandline Interface'
    prompt = '> '
    file = None

    def preloop(self):
        self.program = PrjRem()
        self.program.readConf()

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

if __name__ == '__main__':
    PrjRemCMD().cmdloop()