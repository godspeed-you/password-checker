#!/usr/bin/python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
"""
This module checks your list of passwords at https://haveibeenpwned.com/
and returns how many times the password of a user has been found in the
database.
"""

class CheckPwned(object):
    """
    Loads and checks a set of logins if they have been pwned.
    """

    def __init__(self):
        from collections import namedtuple
        self.hash_elements = "hash, pre, post"
        self.answer_elements = "is_known, count"
        self.elements = namedtuple("elements", self.hash_elements)
        self.hash_answer = namedtuple("hash_answer", self.answer_elements)

        self.hashes = {}
        self._vulnerable = []

    def _create_hashes(self, passwords):
        from hashlib import sha1
        def _create_hash(password):
            psswd = sha1()
            psswd.update(password)
            return psswd.hexdigest()

        for user, password in passwords.iteritems():
            psswd_hash = _create_hash(password)
            prefix = psswd_hash[:5].upper()
            postfix = psswd_hash[5:].upper()
            self.hashes[user] = self.elements(hash=psswd_hash, pre=prefix, post=postfix)

    def _is_vulnerable(self, answer, post):
        for element in answer:
            if post in element:
                count = int(element.split(':')[1])
                return self.hash_answer(is_known=True, count=count)
        return self.hash_answer(is_known=False, count=None)

    def load(self, passwords):
        """
        Read a dictionary of Username:Passwords pairs to check
        """
        self._create_hashes(passwords)

    def _check_hashes(self):
        import requests
        for user, hash_list in self.hashes.iteritems():
            check_answer = requests.get('https://api.pwnedpasswords.com/range/%s' % hash_list.pre)
            check_answer = check_answer.content.split('\r\n')
            element = self._is_vulnerable(check_answer, hash_list.post)
            if element.is_known:
                self._vulnerable.append((user, element.count))
        return self._vulnerable

    def result(self):
        """
        This method just prints the result of the password checking
        """
        result = self._check_hashes()
        for user, count in result:
            print "User %s uses a leaked password. Used in %d entries." % (user, count)

def main():
    """
    Actually check passwords of a given csv file. This file must contain at
    least Username and Password and additionally a header line. E.g.:

    Username,Password,Comment
    myUser,myPassword,this is a example login

    You can simply use the default file in this project. If this file exists, it will be preferred.
    You can also call it with the password file as an argument.
    """
    import csv
    import sys

    if file('password_list.csv'):
        csv_file = 'password_list.csv'
    elif len(sys.argv) > 1:
        csv_file = sys.argv[1]
    else:
        csv_file = raw_input("CSV File with Passwords: ")

    creds_to_check = {}

    with open(csv_file, mode='r') as content:
        csv_reader = csv.DictReader(content)
        for line in csv_reader:
            creds_to_check.setdefault(line.get('Username'), line.get('Password'))

    psswd_check = CheckPwned()
    psswd_check.load(creds_to_check)
    psswd_check.result()

main()
