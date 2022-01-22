# Justin La Zare

import sys
import hashlib
import itertools

from os import path
from mmap import ACCESS_READ, mmap
from tqdm import tqdm

# Prevent user from accidentally involking slash.py
if __name__ != '__main__':
    exit()

formats = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']

if len(sys.argv) != 4:
    print('Usage: py ./slash.py <format> <hash-file> <wordlist>', end='\n\n')
    print('Formats:')
    for f in formats:
        print('-', f)
    exit()

# py ./slash.py something something something

# Make sure user provided a supported hashing algorithm
if sys.argv[1].lower() not in formats:
    print('Invalid format provided')
    exit()

# Make sure the user provided a proper hash file
if not path.exists(sys.argv[2]) or not path.isfile(sys.argv[2]):
    print('Hash file not found')
    exit()

# Make sure the user provided a proper wordlist
if not path.exists(sys.argv[3]) or not path.isfile(sys.argv[3]):
    print('Wordlist file not found')
    exit()

# Example: py ./slash.py md5 hashes.txt wordlist.txt
form = sys.argv[1].lower()  # Hash format
hashPath = sys.argv[2]  # Path to file of hashes
wordlistPath = sys.argv[3]  # Path to wordlist to check hashes against

hashes = []  # List of hashes to be cracked
cracked = {}  # Dictionary of hash-password pairs once cracked

# Functions


def checkPassword(word):
    # Hash word from wordlist using the format
    hashObject = getattr(hashlib, form)(word)

    # Returns the hash in string form
    hash = hashObject.hexdigest()

    # Checks if hash is in the list of hashes we are cracking
    if hash in hashes:
        word = word.decode('utf-8')
        cracked[hash] = word
        # Print the word and its cracked hash
        print(word, hash)


# Open the hash file
hashFile = open(hashPath)

# Add all hashes to a list
for hash in hashFile.readlines():
    hashes.append(hash.replace('\n', ''))

print(format('CRACKING ' + form.upper() + ' HASHES', '=^40'))
print('*', len(hashes), 'hashes loaded')

wordlistFile = open(wordlistPath, errors='replace')

# Maps file to memory, reduces I/O file loading times
mm = mmap(wordlistFile.fileno(), 0, access=ACCESS_READ)

words = iter(mm.readline, b'')  # List of words from wordlist
pbar = tqdm(words, unit=' hashes')  # Turn wordlist into progress bar

# Loops through all the lines in the wordlist
for line in pbar:
    word = line.strip()  # Remove whitespace and \n from word

    # Converts word to hash and checks if it is in hashes list
    checkPassword(word)

    if (len(cracked) == len(hashes)):
        # Exits for loop when all hashes are cracked
        print('All passwords cracked')
        break

charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'


def generatePasswords(length):
    return itertools.combinations_with_replacement(charset, length)


print('* Unable to crack all passwords, beginning brute force')

# Start brute forcing passwords starting at 1 char to until it either finds the remaining hashes or user aborts
print(format('BRUTE FORCE', '=^40'))
passLength = 1
while len(cracked) < len(hashes):
    print('Cracking passwords that are', passLength, 'character(s)')
    pbar = tqdm(generatePasswords(passLength), unit=' hashes')

    for word in pbar:
        # Turn word tuple into bytes object
        word = ''.join(word).encode('utf-8')
        word = word.strip()  # Remove whitespace and \n from word

        # Converts word to hash and checks if it is in hashes list
        checkPassword(word)

        if (len(cracked) == len(hashes)):
            # Exits for loop when all hashes are cracked
            print('All passwords cracked')
            break

    passLength += 1  # Add 1 to password length to brute force

print('Finished cracking')
