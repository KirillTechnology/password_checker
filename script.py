import requests
import hashlib

# Reads passwords from './to_check.txt' (new line - new password) 
# and checks if the password has been leaked by finding it in 
# haveibeenpwned.com database via their API

def request_api_data(query_char):
    '''
    Requests data leaked passwords by first 5 chars of password hash
    '''
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check api anf try again')
    return res


def pwned_count(hashes_dirty, hash_to_check):
    '''
    If the password was found in the database 
    counts how many times was the password leaked
    '''
    for line in hashes_dirty.text.splitlines():
        h,n = line.split(':')
        if h == hash_to_check[5:]:
            return n
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    start, end = sha1password[:5], sha1password[5:]
    response = request_api_data(start)
    return pwned_count(response, sha1password)


def main():
    try:
        with open('./to_check.txt', mode='r') as x:
            passwords = x.read().splitlines()
    except FileNotFoundError as e:
            print('File not found')

    for password in passwords:
        count = pwned_api_check(password)
        if count:
            print(f'! The password \'{password}\' was found {count} times - Change the password')
        else:
            print(f'+ The password \'{password}\' is secure')


if __name__ == '__main__':
    main()
print()