# PwdPwnd

In August '17, Troy Hunt released a huge list of SHA1 hashes he compiled from various password leaks over the last years. The list can be downloaded from his [website](https://haveibeenpwned.com/Passwords). Furthermore, one can easily check whether their password appears in the list via an online form Troy provides on the same page.

However, as Troy (rightfully) notes, one should beware to provide passwords to any third party, himself included. To make it easy for people to check whether their passwords are on the list without sharing their passwords with anyone, I created this small Python tool. It takes passwords from the user, hashes them with SHA1, and searches for those hashes in the list that Troy provided - all locally, no Internet required.

## Requirements
1. Python3 - Python 2 might work, but hasn't been tested by me. Let me know!
2. Troy Hunt's big password list - can be downloaded [directly](https://downloads.pwnedpasswords.com/passwords/pwned-passwords-1.0.txt.7z) or as a [torrent](https://downloads.pwnedpasswords.com/passwords/pwned-passwords-1.0.txt.7z.torrent).

## Usage
`python PwdPwnd.py ~/Downloads/pwned-passwords-1.0.txt`

The script takes one single argument, the path to the downloaded (and extracted) hash list file. Once executed, it'll continuously ask for passwords, and for each one will say whether it was found in the hash list. To quit, simply don't input a password and just hit <kbd>ENTER</kbd>.

## Case sensitivity
By default, the script only looks for the password as typed. However, by editing the code and changing the value of `case_sensitive` value from `True` to `False`, one can check all possible case permutations of a password for presence in the list.