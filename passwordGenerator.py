
import secrets
import string

def xkcdstyle(numwords=4, delimiter=' ', caseselection='lower', dict='/usr/share/dict/words'):
    """
    Generate xkcd style password
        On standard Linux systems, use dictionary file '/usr/share/dict/words'
        Other platforms may need to provide their own word-list.
    """
    with open(dict) as f:
        #   compose words[] based on caseselection
        #
        match caseselection:
            case 'upper':
                words = [word.strip().upper() for word in f]
            case 'first':
                words = [word.strip().title() for word in f]
            case _:
                words = [word.strip().lower() for word in f]
    #   compose the password from words[] and delimiter
    #
    password = delimiter.join(secrets.choice(words) for i in range(numwords))
    return password

def randomstyle(numchars=16, specialchar=True):
    """
    Generate random string/password
    """
    alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits
    if specialchar:
        alphabet = alphabet + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(numchars))
    return password

def demo():
    """
    demo/test
    """

    cases = ['lower', 'first', 'upper']
    numchars = [12, 16, 20]
    numpasswords = 10

    for case in cases:
        print(f"\n\n-----  Xkcd passwords with {case} case -----")
        for i in range(numpasswords):
            print(f"password[{i:2}]: {xkcdstyle(4, '.', case)}")

    for num in numchars:
        print(f"\n\n----- Random passwords with length {num} -----")
        for i in range(numpasswords):
            print(f"password[{i:2}]: {randomstyle(num)}")


if __name__ == "__main__":
    demo()