"""
Module Docstring
"""

__author__ = "Jay S. Liu"
__version__ = "0.1.0"
__license__ = "MIT"

import argparse
import gnupg
import os
import re
import sys
from configparser import ConfigParser
from datetime import datetime
from pathlib import Path
from sqlite_utils import Database

DefaultEntry = {
    "service": None,
    "username": None,
    "password": None,
    "tag": None,
    "note": None,    
}

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
    key = cfg.get_config("ENCRYPTION_KEY", "key")
    return gnupg_home, keyring, recipients, symmetric_encryption, key

class GPGCipher(object):
    def __init__(self, gnupghome=None, keyring=None, recipients=None, symmetric=None): 
        self.gnupghome = gnupghome
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
            return f"encription error with status: {crypted.status}"

    def decrypt(self, data, passphrase=None, file=False):
        if self.gnupghome:
            cipher = gnupg.GPG(gnupghome=self.gnupghome, keyring=self.keyring)
        else:
            cipher = gnupg.GPG()
        if self.symmetric == 'True':
            #print(f"### SYMMETRIC decryption ###")
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
        else:
            #print(f"### PUB-KEY decryption ###")
            if file:
                clear = cipher.decrypt_file(
                    open(data, 'rb'),
                )
            else:
                clear = cipher.decrypt(
                    data,
                )
        if clear.ok:
            return clear.data.decode()
        else:
            return f"encription error with status: {clear.status}"
    
def EncryptPassword(data, cfgfile):
    '''
    Encrypt the given data/string of password with cipher
    '''
    home, keyring, recipients, symmtric, key = getGPGconfig(cfgfile)
    cipher = GPGCipher(home, keyring, recipients, symmtric)
    encoded = cipher.encrypt(data, key)
    #print(f"encrypting password: {data}")
    return encoded

def DecryptPassword(data, cfgfile, file=None):
    '''
    Decrypt the given data/string of encoded password with cipher.
    '''
    home, keyring, recipients, symmtric, key = getGPGconfig(cfgfile)
    cipher = GPGCipher(home, keyring, recipients, symmtric)
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

def init(dbfile, cfgfile):
    my_pass = PassCfg(dbfile, cfgfile)
    my_pass.list_config()
    my_pass.check_table()

def showAll(dbfile, cfgfile=None, showpassword=False):
    """
    Display all entries in dbfile
    """
    db = Database(dbfile)
    results = db.query("select * from ACCOUNT")
    displayResults(results, cfgfile, showpassword)

def fileImport(dbfile, cfgfile, datafile, username, tag=None, note=None, dir=None):
    """
    Import one pwd file to db
        -- no check on exist or not
        -- datafile like service.gpg
    """
    #   check if datafile with extention '.gpg'
    dirName = os.path.dirname(datafile)
    filename = os.path.basename(datafile)
    name, ext = os.path.splitext(filename)
    if ext == '.gpg':
        entry = DefaultEntry
        date = f'{datetime.today():%Y-%m-%d}'
        clear = DecryptPassword(datafile, cfgfile, file=True)
        password = EncryptPassword(clear, cfgfile)
        #   compose values for row
        #
        entry["service"] = name
        entry["username"] = username if username else 'Import'
        entry["password"] = password
        #   set up proper tag
        if dir:
            #   remove prefix/dir, suffix/filename, then find tag
            importTag = datafile.replace(dir, '').replace(filename, '').replace('/', ' ').strip()
            #   add import and option tag
            importTag = f"{tag} {importTag}" if tag else f"{importTag}"
        else:
            importTag = tag if tag else "noTag"
        entry["tag"] = importTag.strip()
        #   setup note
        entry["note"] = f"Imported on {date}, {note}".strip() if note else f"Imported on {date}"
        #   insert to Db
        db = Database(dbfile)
        print(f"--- insert following entry to DB {dbfile}")
        print(f"  service      username       tag         note")
        print(f"{entry["service"]}, {entry["username"]},  {entry["tag"]}, {entry["note"]}")
        db['ACCOUNT'].insert(entry) 
    else:
        sys.exit(99, f"imported file {datafile} without extention .gpg")

def dirImport(dbfile, cfgfile, directory, username, tag=None, note=None):
    """
    Import one pwd file to db
        -- no check on exist or not
        -- datafile like service.gpg
    """
    #   check if directory is real
    if not os.path.isdir(directory):
        sys.exit(99, f"{directory} is NOT a directory, see you next time ...")
    
    #   walk thru all files in directory and process
    for root, _dirs, files in os.walk(directory):
        for file in files:
            datafile = f"{root}/{file}"
            print(f"Processing file: {datafile}")
            name, ext = os.path.splitext(file)
            if ext == '.gpg':
                fileImport(dbfile, cfgfile, datafile, username, tag, note, directory)
            else:
                print(f"    skipping file {file} -- not gpg file")

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
    filename = f"{dir}/{entry['service']}.gpg"
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
    '''
    dirs = re.split(r'\s+', tag.strip())
    dir = '/'.join(dirs)
    '''

def exportDb(dbfile):
    """
    
    """
    db = Database(dbfile)
    for entry in db['ACCOUNT'].rows:
        print(entry)
        exportEntry(entry, root='_Export')

def search(dbfile, cfgfile, service=None, username=None, tag=None, showpassword=False):
    """
    Query on service, username or tag
    """
    if service and username and tag:
        whereClause = f"where service='{service}' and username='{username}' and tag like '%{tag}%'"
    elif service and username:
        whereClause = f"where service='{service}' and username='{username}'"
    elif service and tag:
        whereClause = f"where service='{service}' and tag like '%{tag}%'"
    elif username and tag:
        whereClause = f"where username like '%{username}%' and tag like '%{tag}%'"
    elif service:
        whereClause = f"where service like '%{service}%'"
    elif tag:
        whereClause = f"where tag like '%{tag}%'"
    else:
        print(f"--- No support on query with: ---")
        print(f"    service: {service}")
        print(f"    username: {username}")
        print(f"    tag: {tag}")
        return 
    selectPrefix = f"select * from ACCOUNT"
    myQuery = f"{selectPrefix} {whereClause}"
    print(f"\nquery: {myQuery}\n")
    db = Database(dbfile)
    _results = db.query(myQuery)
    results = [x for x in _results]
    displayResults(results, cfgfile, showpassword)

def delete(dbfile, cfgfile, service=None, username=None, tag=None, showpassword=False, backup=False, backupDir='./_DELETED'):
    """
    Query on service, username or tag
    """
    deleted = []
    if service and username and tag:
        whereClause = f"where service='{service}' and username='{username}' and tag like '%{tag}%'"
    elif service and username:
        whereClause = f"where service='{service}' and username='{username}'"
    elif service:
        whereClause = f"where service like '%{service}%'"
    elif tag:
        whereClause = f"where tag like '%{tag}%'"
    else:
        print(f"--- No support on remove with: ---")
        print(f"    service: {service}")
        print(f"    username: {username}")
        print(f"    tag: {tag}")
        return 
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
        print(f"DELETE: {e['service']:30} {e['username']:20} {e['tag']:20} {e['note']}\n")
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


def insertEntry(dbfile, cfgfile):
    """
    Insert one entry to db
    """
    date = f'{datetime.today():%Y-%m-%d}'
    entry = {}
    service = input("Service: ")
    print()
    username = input("Username: ")
    print()
    clear = multilineInput(f"Password")
    print()
    tag = input("Tag: ")
    print()
    note = multilineInput("Note")
    password = EncryptPassword(clear, cfgfile)
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


def main(args):
    """ Main entry point of the app """
    print(args)
    dbfile = args.dbfile
    cfgfile = args.cfgfile
    show = args.show
    showpassword = args.showpassword
    importFile = args.importFile
    importDir = args.importDir
    export = args.export
    insert = args.insert
    remove = args.remove
    backup = args.backup
    query = args.query
    service = args.service
    username = args.username
    tag = args.tag
    note = args.note

    init(dbfile, cfgfile)
    if show:
        showAll(dbfile, cfgfile, showpassword)
    if query:
        search(dbfile, cfgfile, service, username, tag, showpassword)
    if remove:
        deleted = delete(dbfile, cfgfile, service, username, tag, showpassword, backup)
    if importFile:
        fileImport(dbfile, cfgfile, importFile, username, tag. note)
    if importDir:
        dirImport(dbfile, cfgfile, importDir, username, tag, note)
    if export:
        exportDb(dbfile)
    if insert:
        insertEntry(dbfile, cfgfile)

if __name__ == "__main__":
    
    """ This is executed when run from the command line """
    parser = argparse.ArgumentParser(description="Application description")

    parser.add_argument("-d",
        "--dbfile",
        default="database.db",
        help="File name of the database")
    parser.add_argument("-c",
        "--cfgfile",
        default="config.ini",
        help="File name of the configuration")
    parser.add_argument("-q",
        "--query",
        default=False,
        action="store_true",
        help="Query on service, username and/or, tag")
    parser.add_argument(
        "--insert",
        default=False,
        action="store_true",
        help="Insert one entry to Db -- all input from keyboard")
    parser.add_argument("-r",
        "--remove",
        default=False,
        action="store_true",
        help="Delete entries by service, username and/or, tag")
    parser.add_argument(
        "--backup",
        default=True,
        action = "store_false",
        help="Backup on remove -- Default to True")
    parser.add_argument(
        "--show",
        default=False,
        action="store_true",
        help="Show all entries")
    parser.add_argument(
        "--showpassword",
        default=False,
        action="store_true",
        help="Show password when display")
    parser.add_argument(
        "--importDir",
        default=None,
        help="Directory name for import")
    parser.add_argument(
        "--importFile",
        default=None,
        help="File name for import")
    parser.add_argument(
        "--export",
        default=False,
        action = "store_true",
        help="Export entries to files")
    parser.add_argument(
        "--service",
        default=None,
        help="Default service name")
    parser.add_argument("-u",
        "--username",
        default=None,
        help="Default username")
    parser.add_argument("-t",
        "--tag",
        default=None,
        help="Default tag")
    parser.add_argument("-n",
        "--note",
        default=None,
        help="Default note")    # Optional verbosity counter (eg. -v, -vv, -vvv, etc.)
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Verbosity (-v, -vv, etc)")

    args = parser.parse_args()
    main(args)


