# BitWarden Vault Health Check

A simple script that can check your BitWarden vault for the following: 
- Duplicate Passwords
- Hacked (Pwned) passwords

## Dependencies
- Python3 (3.6+) 
- [BitWarden CLI](https://bitwarden.com/help/article/cli/)

The script uses the BitWarden cli under the hood, it needs to be pointed to the executables path.

## Checks
Only items of type 'password' are iterated over. All passwords are hashed with
SHA-1 and the hashes are then used for all checks. A report is generated of the following:
### Duplicate Passwords
The items with the same password hashes will be grouped together. The report includes
the full path and name of items that have the same password. Example:
```
*****SHA1-of-password*****
 - path/to/items
 - that/share
 - the/same/password
```

### *Pwned* Passwords
The [HaveIBeenPwned](https://havibeenpwned.com) api is used to detect this. The API uses
K-Anonimity, so the actual password or it's entire SHA is never sent to the server!

If you are interested on K-Anonimity and HaveIBeenPwned, refer to the articles below:
- [CloudFlare K-Anonimity Blog](https://blog.cloudflare.com/validating-leaked-passwords-with-k-anonymity/)
- [HaveIBeenPwned Privacy Policy](https://haveibeenpwned.com/Privacy)

#### Tldr
The password is hashed client-side. The first 5 characters of the password is sent to the server.
The server then returns all the hashes it has that start with the said 5 characters. The match 
is then done on the client side. The password is never sent, nor enough information about
the password to be able to reverse any information.

Sample output:
```
The following password have been PWNED:
 - these/listed/passwords
 - have/been/pwned
```

## Usage
```bash
$ ./health-check.py --help
usage: health-check.py [-h] [--bitwarden BITWARDEN] [--output OUTPUT] [--server SERVER] [--verbose] [--timeout TIMEOUT] username password

A BitWarden vault Health Checker. Please make sure the vault is unlocked prior to running this check.

positional arguments:
  username
  password

optional arguments:
  -h, --help            show this help message and exit
  --bitwarden BITWARDEN, -b BITWARDEN
                        Path to the bitwarden cli
  --output OUTPUT, -o OUTPUT
                        File to store all output to
  --server SERVER, -s SERVER
                        Point BitWarden-cli at a different instance of BitWarden
  --verbose, -v         Enable verbose output
  --timeout TIMEOUT, -t TIMEOUT
                        Max time to wait for requests before raising error
```

`username` and `password` is required to login to the account from the cli.

- `--bitwarden` -> Should be set to the location of the bitwarden cli exe. Not required if
it is in PATH.
- `--output` -> Stores the output to the specified file.
- `--server` -> For self-hosted instances, can be used to update bitwarden cli to point to 
that instance.
- `--verbose` -> Increase amount of logs shown.
- `--timeout` -> Time to wait for requests to return (seconds)

### Sample Run
```bash
$ python3 healh-check.py \
   --bitwarden='/usr/local/bin/bw' \
   --server='https://bitwarden.com' \
   --output='/home/user/report.txt' \
   --timeout=5 \
   --verbose \
   user@example.com myS3cureVaultPassword

Attempting to log in ...
Successfully logged into BitWarden!
Pulling down latest vault ...
Fetching folder information ...
Fetching all items ...
Generating report ...

The following password are duplicated:
*****5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8*****
 - Social Media/Facebook
 - Social Media/Twitter

*****cbfdac6008f9cab4083784cbd1874f76618d2a97*****
 - Email/Hotmail
 - Email/Gmail

*****d30deb4de9e752add3831275f0be5659a20d5248*****
 - Gaming/Steam
 - Email/Outlook
 - Social Media/Snapchat


The following password have been PWNED:
 - Gaming/Blizzard
 - School/Blackboard
 - Banking/Online Banking/HSBC
```

## License
[MIT](LICENSE)

## Issues
Feel free to open issue if you encounter anything. This was more of a quick side project
but I'll try my best to fix bugs. Pull requests are always welcome.