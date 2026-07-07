# aesKrbKeyGen

```
aesKrbKeyGen -h
usage: aesKrbKeyGen [-h] -realm REALM [-user USER] [-computer COMPUTER] -pass PASSWORD [-i I]

Generate NTLM hashes and AES128/256 Kerberos keys for an AD account using a plaintext password

options:
  -h, --help          show this help message and exit
  -realm REALM        Kerberos realm name
  -user USER          Case sensitive sAMAccountName
  -computer COMPUTER  FQDN hostname (ex: dc01.cerbere.local)
  -pass PASSWORD      Valid cleartext or hex account password
  -i I                Iterations to perform for PBKDF2
```
