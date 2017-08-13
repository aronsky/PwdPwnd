#!/usr/bin/python3
# Copyright (c) 2017 Lev Aronsky
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
A small tool for locally checking passwords against leaked hash lists. Developed with
Troy Hunt's big hash list (https://haveibeenpwned.com/Passwords) in mind. The file is
searched using Python's bisect (binary search), so it has to be sorted!
"""

import itertools
import hashlib
import getpass
import bisect
import mmap
import sys

class HashList(object):
    """
    A wrapper around a sorted list of hashes.
    """

    def __getitem__(self, index):
        "x.__getitem__(y) <==> x[y]"
        index = index * (self._hash_size + self._divider_size)
        return self._hashlist[index:index + self._hash_size]

    def __init__(self, filename: str, hashfunc=hashlib.sha1) -> None:
        "Initialize the hashlist."
        with open(filename, 'rb') as hashfile:
            self._hashlist = mmap.mmap(hashfile.fileno(), 0, access=mmap.ACCESS_READ)
            sample_line = hashfile.readline()
            sample_hash = "".join(itertools.takewhile(str.isalnum, sample_line.decode('ascii')))
            divider = "".join(itertools.dropwhile(str.isalnum, sample_line.decode('ascii')))

        if str.isupper(sample_hash):
            self._hash = lambda x: hashfunc(x.encode('ascii')).hexdigest().upper().encode('ascii')
        else:
            self._hash = lambda x: hashfunc(x.encode('ascii')).hexdigest().lower().encode('ascii')

        self._hash_size = len(self._hash(''))
        self._divider_size = len(divider)

    def __len__(self):
        "Return len(self)."
        return len(self._hashlist) // (self._hash_size + self._divider_size)

    def check_password(self, password: str, case_sensitive=True) -> bool:
        """
        password: Check whether a password is in the hash list.

        case_sensitive: if False, compute all the possible case permutations,
        and check all of them against the hash list.
        """

        if not case_sensitive:
            permutations = ["".join(combo) for combo in
                            itertools.product(*[[c.lower(), c.upper()] for c in password])]
        else:
            permutations = [password]

        for password in permutations:
            pwdhash = self._hash(password)
            if self[bisect.bisect_left(self, pwdhash)] == pwdhash:
                return True

        return False


def main(hashlist_filename: str) -> None:
    """
    hashlist_filename: the location of the file containing a sorted list of hashes.

    Gets passwords from user and checks them against the list, until an
    empty input is detected.
    """
    hashlist = HashList(hashlist_filename)
    while True:
        pwd = getpass.getpass()
        if not pwd:
            break
        if hashlist.check_password(pwd):
            print("Found!")
        else:
            print("Not found!")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: {} <sorted hashlist file>".format(__file__))
        sys.exit(-1)

    main(sys.argv[1])
