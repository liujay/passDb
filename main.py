"""
Module Docstring
"""

__author__ = "Jay S. Liu"
__version__ = "0.1.0"
__license__ = "MIT"

import argparse
import ast
import gnupg
import json
import os
import re
import sys
import tempfile
from configparser import ConfigParser
from datetime import datetime
from pathlib import Path
from passwordGenerator import randomstyle, xkcdstyle
from sqlite_utils import Database

'''
Use typer for v2
'''
import typer

app = typer.Typer()

class PassCfg:
    def __init__(self, dbfile, configfile, verbose=False):
        self.db = dbfile
        self.configfile = configfile
        self.verbose = verbose

    def set_config(self, section, key, value):
        config_file_path = self.configfile
        config = ConfigParser()
        try:
            with open(config_file_path) as conf:
                config.read(config_file_path)
                config[section][key] = value
                with open(config_file_path, 'w') as conf:
                    config.write(conf)
        except (OSError, IOError) as e:
            raise Exception("Couldn't find path to config.ini.") from e
        if self.verbose:
            print(f"  SET config[{section}, {key}] = {value}", file=sys.stderr)

    def get_config(self, section, key):
        config_file_path = self.configfile
        config = ConfigParser()
        try:
            with open(config_file_path) as conf:
                config.read(config_file_path)
                value = config.get(section, key)
                if self.verbose:
                    print(f"  GET config[{section}, {key}] = {value}", file=sys.stderr)
                return value
        except (OSError, IOError) as e:
            raise Exception("Couldn't find path to config.ini.") from e
        
    def list_config(self):
        config_file_path = self.configfile
        config = ConfigParser()
        print(f"\n--- Configuration ---")
        print(f"Database file: {self.db}")
        print(f"Contents of config file: {self.configfile}")
        try:
            with open(config_file_path) as conf:
                config.read(config_file_path)
                for section in config.sections():
                    print(f"    {section}")
                    for key in config[section]:
                        _value = config.get(section, key)
                        value = _value if _value else '-NULL-'
                        print(f"        {key} :   {value}")
                    print()
        except (OSError, IOError) as e:
            raise Exception("Couldn't find path to config.ini.") from e

    def __repr__(self):
        return f"<PassDB: {self.db}>\n<Cfg file: {self.configfile}>"

    def check_table(self):
        '''
        Check if ACCOUNT table lives in db file and create it if NOT
        '''
        db = Database(self.db)
        db['ACCOUNT'].create({
            "id": int,
            "service": str,
            "username": str,
            "password": str,
            "tag": str,
            "note": str,
        }, pk="id", if_not_exists=True)

def getGPGconfig(cfgfile):
    """
    find all GPG config values:
        gnupg_home
        keyring
        recipients
        symmetric_encryption
        key
    """
    cfg = PassCfg('dontcare', cfgfile)
    gnupg_home = cfg.get_config("GPG", "gnupg_home")
    keyring = cfg.get_config("GPG", "keyring")
    recipients = cfg.get_config("GPG", "recipients")
    symmetric_encryption = cfg.get_config("GPG", "symmetric_encryption")
    key = ast.literal_eval(cfg.get_config("ENCRYPTION_KEY", "key"))
    return gnupg_home, keyring, recipients, symmetric_encryption, key

class GPGCipher(object):
    def __init__(self, gnupghome=None, keyring=None, recipients=None, symmetric=None): 
        self.gnupghome = os.path.expanduser(gnupghome)
        self.keyring = keyring
        self.recipients = recipients
        self.symmetric = symmetric

    def __repr__(self):
        return f"<GPGhome: {self.gnupghome}>\n<Keyring: {self.keyring}>"
 
    def encrypt(self, data, passphrase=None):
        if self.gnupghome:
            cipher = gnupg.GPG(gnupghome=self.gnupghome, keyring=self.keyring)
        else:
            cipher = gnupg.GPG()
        if self.symmetric == 'True':
            #print(f"### SYMMETRIC encryption ###")
            crypted = cipher.encrypt(
                data,
                recipients = None,
                symmetric = True,
                passphrase = passphrase
            )
        else:
            #print(f"### PUB-KEY encryption ###")
            crypted = cipher.encrypt(
                data,
                recipients = self.recipients,
                always_trust = True
            )
        if crypted.ok:
            return crypted.data.decode()
        else:
            print(f"encription error with status: {crypted.status}")
            print(f"  !!! Check if key cache expired !!!")
            sys.exit(96)

    def decrypt(self, data, passphrase=None, file=False):
        if self.gnupghome:
            cipher = gnupg.GPG(gnupghome=self.gnupghome, keyring=self.keyring)
        else:
            cipher = gnupg.GPG()
        #   no need to distinguish between pub- or symmetric- encrypted data
        if file:
            clear = cipher.decrypt_file(
                open(data, 'rb'),
                passphrase = passphrase
            )
        else: 
            clear = cipher.decrypt(
                data,
                passphrase = passphrase
            )
        if clear.ok:
            return clear.data.decode()
        else:
            print(f"decription error with status: {clear.status}")
            print(f"  !!! Check if key cache expired !!!")
            sys.exit(97)
    
def EncryptPassword(data, cfgfile, transcode=False):
    '''
    Encrypt the given data/string of password with cipher
    '''
    home, keyring, recipients, symmetric, key = getGPGconfig(cfgfile)
    #   negate symmetric to achieve trancode
    #
    if transcode:
        symmetric = 'False' if symmetric=='True' else 'True'
    cipher = GPGCipher(home, keyring, recipients, symmetric)
    encoded = cipher.encrypt(data, key)
    #print(f"encrypting password: {data}")
    return encoded

def DecryptPassword(data, cfgfile, file=None):
    '''
    Decrypt the given data/string of encoded password with cipher.
    '''
    home, keyring, recipients, symmetric, key = getGPGconfig(cfgfile)
    cipher = GPGCipher(home, keyring, recipients, symmetric)
    #print(f"\n----- cipher: {cipher.__repr__} -----\n")
    if file:
        clear = cipher.decrypt(data, key, file=True)
    else:    
        clear = cipher.decrypt(data, key)
    #print(f"decrypting password: {clear}")
    return clear

def displayResults(results, cfgfile=None, showpassword=False):
    """
    Display query results
        results should be list of entries, NOT a generator
    """
    if showpassword:
        print(f"id  service         username        tag         note")
        print(f"password")
    else:
        print(f"id  service         username        tag         note")
    if results:
        for r in results:
            #   convert null value to string '---Null---'
            for col in ['id', 'service', 'username', 'tag', 'note']:
                r[col] = r[col] if r[col] else '-- Null --' 
            print(f"{r['id']:3}:: {r['service']}:: {r['username']}:: {r['tag']}:: {r['note']}")
            if showpassword and cfgfile:
                password = DecryptPassword(r['password'], cfgfile)
                print(f"{password}")
    else:
        print(f"--- Empty result ---")

def insertEntry(dbfile, service, password, username=None, tag=None, note=None, dir=None):
    """
    Compose and insert one entry to Db
    """
    entry = {}
    date = f'{datetime.today():%Y-%m-%d}'
    entry["service"] = service.strip()
    entry["username"] = username.strip() if username else 'Import'
    entry["password"] = password

    entry["tag"] = tag.strip()
    #   setup note
    entry["note"] = f"Imported on {date}, {note}".strip() if note else f"Imported on {date}"
    #   insert to Db
    db = Database(dbfile)
    print(f"--- insert following entry to DB {dbfile}")
    print(f"  service      username       tag         note")
    print(f"{entry["service"]}, {entry["username"]},  {entry["tag"]}, {entry["note"]}")
    db['ACCOUNT'].insert(entry) 

def exportEntry(entry, root=None):
    """
    Export one entry to a file where
        dir is composed from tag, and
        baseame is service
    """
    dirs = re.split(r'\s+', entry['tag'].strip())
    dir = '/'.join(dirs)
    if root:
        dir = f"{root}/{dir}"
    #   take care of '/' in service that was used as basename of file
    #       eg, someone uses "https://any.com/app" as service name
    basename = entry['service'].replace('/','_')
    filename = f"{dir}/{basename}.gpg"
    print(f"entry id: {entry['id']}, service: {'service'}, tag: {entry['tag']}")
    print(f"exporting entry to file: {filename}")
    #   creat dir if not exist
    try:
        os.makedirs(dir)
    except FileExistsError:
        pass
    if type(entry['password']) is str:
        with open(filename, "w") as f:
            f.write(entry['password'])
    else:
        print(f"--- skip entry['service'] with password of type {type(entry['password'])} ---")

def buildWhereClause(id=None, service=None, username=None, tag=None):
    """
    Build the where clause for search/query
        -- for search and delete query
    """
    if id:
        whereClause = f"where id='{id}'"
    elif service and username and tag:
        whereClause = f"where service='{service}' and username='{username}' and tag like '%{tag}%'"
    elif service and username:
        whereClause = f"where service='{service}' and username='{username}'"
    elif service and tag:
        whereClause = f"where service='{service}' and tag like '%{tag}%'"
    elif username and tag:
        whereClause = f"where username like '%{username}%' and tag like '%{tag}%'"
    elif service:
        whereClause = f"where service like '%{service}%'"
    elif username:
        whereClause = f"where username like '%{username}%'"
    elif tag:
        whereClause = f"where tag like '%{tag}%'"
    else:
        print(f"--- No support on query on: ---")
        print(f"    id: {id}")
        print(f"    service: {service}")
        print(f"    username: {username}")
        print(f"    tag: {tag}")
        return None
    return whereClause

def multilineInput(opening='content'):
    """
    Take multiple lines input
    """
    print(opening)
    print(f"Enter/Paste your {opening}. Ctrl-D or Ctrl-Z (windows?) to save it.")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        lines.append(line)
    #   combine all lines to one sting
    result = f"{'\n'.join(lines)}"
    return result

def readFile(fileName):
    """
    read and return text from file
    """
    with open(fileName, 'rb') as f:
        content = f.read()
    return content

def entry2jsonFile(entry, tempFile):
    """
    Export decoded password entry to a json file for editing
        id was removed before export
    """
    with open(tempFile, 'w') as f:
        json.dump(entry, f, indent=4, sort_keys=True)    

def jsonFile2entry(tempFile):
    """
    Import an entry of password for updating
    """
    f = open(tempFile, 'r')
    entry = json.load(f)
    #   encrypt password before updating db
    return entry

@app.command()
def init(dbfile: str='database.db', cfgfile: str='config.ini', listcfg: bool=True):
    """
    Initialize ACCOUNT table if it does not exist, and
    list config file
    """
    my_pass = PassCfg(dbfile, cfgfile)
    if listcfg :
        my_pass.list_config()
    my_pass.check_table()

@app.command()
def showall(dbfile: str='database.db', cfgfile: str='config.ini', showpassword: bool=False):
    """
    Display all entries in dbfile
    """
    init(dbfile=dbfile, cfgfile=cfgfile)

    db = Database(dbfile)
    results = db.query("select * from ACCOUNT")
    displayResults(results, cfgfile, showpassword)

@app.command()    
def fileimport(datafile: str,
        dbfile: str='database.db', cfgfile: str='config.ini', 
        username: str='', tag: str='', note: str='', dir: str='',
        initdb: bool=True):
    """
    Import one pwd file to db
        -- no check on exist or not
        -- datafile like service.gpg
    """
    if initdb:
        init(dbfile=dbfile, cfgfile=cfgfile)

    #   check if datafile with extention '.gpg'
    _dirName = os.path.dirname(datafile)
    filename = os.path.basename(datafile)
    service, ext = os.path.splitext(filename)
    if service[0] == '.':
        print(f"!!! Ignore dot file: {filename} !!!")
        return None
    elif ext == '.gpg':
        clear = DecryptPassword(datafile, cfgfile, file=True)
    else:   # others are assumed to be clear file
        print(f"  ! Treat file {datafile} as a clear file !")
        clear = readFile(datafile)
    password = EncryptPassword(clear, cfgfile)
    #   set up proper tag
    #
    if dir:
        #   remove prefix/dir, suffix/filename, then find tag
        myTag = datafile.replace(dir, '').replace(filename, '').replace('/', ' ').strip()
        #   add import and option tag
        myTag = f"{tag} {myTag}" if tag else f"{myTag}"
    else:
        myTag = tag if tag else "noTag"
    #   insert to Db
    insertEntry(dbfile, service, password, username, myTag, note)
    return True

@app.command()
def dirimport(directory: str,
        dbfile: str='database.db', cfgfile: str='config.ini', 
        username: str='', tag: str='', note: str=''):
    """
    Import one pwd file to db
        -- no check on exist or not
        -- datafile like service.gpg
    """
    init(dbfile=dbfile, cfgfile=cfgfile)

    #   expand directory
    directory = os.path.expanduser(directory)
    #   check if directory is real
    if not os.path.isdir(directory):
        print(f"----- {directory} is NOT a directory, see you next time ... -----")
        sys.exit(99)
    
    #   walk thru all files in directory and process
    initdb = False
    for root, _dirs, files in os.walk(directory):
        for file in files:
            datafile = f"{root}/{file}"
            print(f"Processing file: {datafile}")
            fileimport(datafile, dbfile, cfgfile, username, tag, note, directory, initdb)


@app.command()
def exportdb(dbfile: str='database.db', cfgfile: str='config.ini',
             directory: str='_Export'):
    """
    export all passwords to files live in {directory}
    """
    init(dbfile=dbfile, cfgfile=cfgfile)

    db = Database(dbfile)
    for entry in db['ACCOUNT'].rows:
        print(entry)
        exportEntry(entry, directory)

@app.command()
def exportentry(dbfile: str='database.db', cfgfile: str='config.ini',
                id: str='', directory: str='_Export'):
    """
    Export one entry by id
    """
    init(dbfile=dbfile, cfgfile=cfgfile)

    db = Database(dbfile)
    #   get the entry by id
    id = int(id)
    try:
        entry = db['ACCOUNT'].get(id)
    except Exception as e:
        print(f"!!! Error: {e} occured \n    when getting id: {id} from Db: {dbfile} !!!")
        print(f"!!!! Check if id: {id} exists in Db !!!!!")
        sys.exit(89)
    #   real job -- export
    print(entry)
    exportEntry(entry, directory)


@app.command()
def transcodedb(dbfile: str='database.db', cfgfile: str='config.ini'):
    """
    Convert pub <--> symmetirc key encryption
    """
    init(dbfile=dbfile, cfgfile=cfgfile)

    db = Database(dbfile)
    for entry in db['ACCOUNT'].rows:
        clear = DecryptPassword(entry['password'], cfgfile)
        #   set trancode to `True` in procedure EncrypPassword to activate it
        #
        password = EncryptPassword(clear, cfgfile, True)
        db['ACCOUNT'].update(entry['id'], {'password': password})
    #
    #   Remind user to update cfgfile
    print(f"\n\n!!! Be sure to update {cfgfile} before next run!!!\n\n")

@app.command()
def search(dbfile: str='database.db', cfgfile: str='config.ini', 
           id: str='', service: str='', username: str='', tag: str='', 
           showpassword: bool=False):
    """
    Search on id, service, username and/or tag
    """
    init(dbfile=dbfile, cfgfile=cfgfile)

    whereClause = buildWhereClause(id, service, username, tag)
    if not whereClause:
        #   invalid whereClause, ie, no support for what were given
        return None
    selectPrefix = f"select * from ACCOUNT"
    myQuery = f"{selectPrefix} {whereClause}"
    print(f"\nquery: {myQuery}\n")
    db = Database(dbfile)
    _results = db.query(myQuery)
    results = [x for x in _results]
    displayResults(results, cfgfile, showpassword)

@app.command()
def remove(dbfile: str='database.db', cfgfile: str='config.ini', 
           id: str='', service: str='', username: str='', tag: str='', 
           showpassword: bool=False, backup: bool=True, backupDir: str='./_DELETED'):
    """
    Delete on id, service, username and/or tag
    """
    init(dbfile=dbfile, cfgfile=cfgfile)

    deleted = []
    whereClause = buildWhereClause(id, service, username, tag)
    if not whereClause:
        #   invalid whereClause, ie, nothing to delete
        return deleted
    selectPrefix = f"select * from ACCOUNT"
    myQuery = f"{selectPrefix} {whereClause}"
    print(f"\nquery: {myQuery}\n")
    db = Database(dbfile)
    _results = db.query(myQuery)
    results = [x for x in _results]
    if not results:
        print(f"\n--- Found NO entry to DELETE ---")
        print(f"--- Have a good one ---\n")
        return deleted
    #   found some entries to delete
    #
    displayResults(results, cfgfile, showpassword)
    print(f"\n--- Found {len(results)} entries to DELETE ---")
    print(f"Let's do it one entry at a time ...\n")
    for e in results:
        print(f"DELETE: {e['id']:3}: {e['service']:30} {e['username']:20} {e['tag']:20} {e['note']}\n")
        selection = input(f"Yes/No ? ")
        if selection and selection[0].lower() == 'y':
            print(f"!!! DELETING entry: {e['service']} !!!\n")
            if backup:
                exportEntry(e, backupDir)
            db['ACCOUNT'].delete(e['id'])
            deleted.append(e)
        else:
            print(f"Skipping entry id: {e['id']}, service: {e['service']}, username: {e['username']}\n")
    #   keep the deleted entries, just in case
    return deleted


@app.command()    
def inputentry(dbfile: str='database.db', cfgfile: str='config.ini', 
               random: bool=False, xkcd: bool=False, editor: bool=False):
    """
    Insert one entry to db -- input by user mostly interactively
    """
    init(dbfile=dbfile, cfgfile=cfgfile)

    cfg = PassCfg('dontcare', cfgfile)
    if random:
        #   get length, punctuation from cfgfile
        length = int(cfg.get_config("PASSWORD_PREFERENCE", "length"))
        punctuation = True if cfg.get_config("PASSWORD_PREFERENCE", "punctuation") == 'True' else False
        clear = randomstyle(length, punctuation)
        print(f" --- random password from generator ---")
    elif xkcd:
        #   get numberwords, delimiter, case, dictionary from cfgfile
        numberwords =  int(cfg.get_config("PASSWORD_PREFERENCE", "numberwords"))
        delimiter = ast.literal_eval(cfg.get_config("PASSWORD_PREFERENCE", "delimiter"))
        caseselection = cfg.get_config("PASSWORD_PREFERENCE", "caseselection")
        dict = cfg.get_config("PASSWORD_PREFERENCE", "dictionary")
        clear = xkcdstyle(numberwords, delimiter, caseselection, dict)
        print(f" --- random password from xkcd generator ---")
    elif editor:
        fp = tempfile.NamedTemporaryFile(delete_on_close=False)
        tempPwdFile = fp.name
        myeditor = cfg.get_config("OTHERS", "editor")
        delay = cfg.get_config("OTHERS", "sleep")
    date = f'{datetime.today():%Y-%m-%d}'
    entry = {}
    service = input("Service: ")
    print()
    username = input("Username: ")
    print()
    if not random and not xkcd and not editor:
        clear = multilineInput("Password: ")
    elif not random and not xkcd and editor:
        print(f"\n\n --- Will open '{myeditor}' for creating password in {delay} seconds ---\n\n")
        os.system(f"sleep {delay}")
        os.system(f"{myeditor} {tempPwdFile}")
        #   looks like vi (and other editor?) adds newline at EOF
        #       let's take care of this
        if myeditor in ['vi', 'vim']:
            os.system(f"truncate -s -1 {tempPwdFile}")
        clear = readFile(f"{tempPwdFile}")
        os.system(f"unlink {tempPwdFile}")
    print(f"--- password: {clear} ---")
    password = EncryptPassword(clear, cfgfile)
    print()
    tag = input("Tag: ")
    print()
    note = input("Note: ")
    print()
    entry["service"] = service
    entry["username"] = username
    entry["password"] = password
    entry["tag"] = tag
    entry["note"] = f"{note}, created on {date}"
    #   insert to Db
    db = Database(dbfile)
    print(f"--- insert following entry to DB {dbfile}")
    print(f"  service      username       tag         note")
    print(f"{entry["service"]}:: {entry["username"]}::  {entry["tag"]}:: {entry["note"]}")
    db['ACCOUNT'].insert(entry) 

@app.command()
def updateentry(dbfile: str='database.db', cfgfile: str='config.ini',
            id: str=''):
    """
    Update one entry
    """
    init(dbfile=dbfile, cfgfile=cfgfile)

    cfg = PassCfg('dontcare', cfgfile)
    myeditor = cfg.get_config("OTHERS", "editor")
    delay = cfg.get_config("OTHERS", "sleep")

    db = Database(dbfile)
    fp = tempfile.NamedTemporaryFile(delete_on_close=False)
    tempFile = fp.name
    id = int(id)
    try:
        entry = db['ACCOUNT'].get(id)
    except Exception as e:
        print(f"!!! Error: {e} occured \n    when getting id: {id} from Db: {dbfile} !!!")
        print(f"!!!! Check if id: {id} exists in Db !!!!!")
        sys.exit(89)
    #   make a copy/backup before updating
    #       creat dir if not exist
    copyDirName = '_copy'
    try:
        os.makedirs(copyDirName)
    except FileExistsError:
        pass
    copyFileName = f"{entry['id']}_{entry['service'].strip()}_{entry['username'].strip()}.json"
    entry2jsonFile(entry, f"{copyDirName}/{copyFileName}")
    #   decrypt password before export to file
    entry['password'] = DecryptPassword(entry['password'], cfgfile)
    #   hide entry's id -- no update on this column
    del entry['id']
    #   export enty to temp/json file for edit
    entry2jsonFile(entry, tempFile)
    print(f"\n\n --- Will open '{myeditor}' for updating in {delay} seconds ---\n\n")
    os.system(f"sleep {delay}")
    os.system(f"{myeditor} {tempFile}")
    entry = jsonFile2entry(tempFile)
    os.system(f"unlink {tempFile}")
    #   encrypt password before update db
    entry['password'] = EncryptPassword(entry['password'], cfgfile)
    db['ACCOUNT'].update(id, entry)

if __name__ == "__main__":
    app()
