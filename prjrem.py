import json, cmd, pyperclip, secrets, string
from Crypto.Cipher import AES
from pathlib import Path


class PrjRem:
    CHAR_SET = '!@#$%s%s%s' % (string.ascii_lowercase, string.digits, string.ascii_uppercase)
    CHAR_SET_LENGTH = len(CHAR_SET) - 1
    PATH_HOME = Path.home().as_posix() + '/.prjrem'
    PATH_CONF = PATH_HOME + '/config'

    def __init__(self):
        self.config = dict()
        self.passwords = dict()
        self.rng = secrets.SystemRandom()
        self.configDefaults = {'location': self.PATH_HOME + '/.prjremDat'}


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
                self.config = json.load(f)
        else:
            Path(self.PATH_HOME).mkdir(exist_ok=True)

    def saveConf(self):
        with Path(self.PATH_CONF).open(mode='w') as f:
            f.write(json.dumps(self.config))

    def readPass(self):
        s = ''
        with Path(self.config['location']).open() as f:
            s = f.read()
        
        # TODO aes
        self.passwords = json.loads(s)

    def savePass(self):
        s = json.dumps(self.passwords)
        with Path(self.config['location']).open(mode='w') as f:
            f.write(s)


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

if __name__ == '__main__':
    PrjRemCMD().cmdloop()