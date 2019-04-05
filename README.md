pasta decryptor for IEncrypt ransomware
======

A recent series of IEncrypt ransomware attacks prompted us to our own implementation of their decryptor.
Since the decryptor binary sent over by the ransomware distributors is obfuscated, it's a little unclear
if it does anything malicious in addition to decrypting the files on disk, so we figured it's a better
idea to run code you can see for yourself.

IEncrypt replaces all non-system files on your computer with an encrypted file of the same length named
<original_filename>.xyzxyz (or some other extenstion). It also places a short ransom note in an adjacent
file named <original_filename>.xyzxyz_readme -- this contains an encrypted AES key that is generated
per-file. The decryptor uses the private key to get the original AES key and opens the file with that.

Note that this decryptor still requires the private key from the ransomware people, so it won't save you
any money. You still need to buy their decryption binary and extract the private key from there.
We hope to have a utility that does this ready soon. In the meantime, you can retrieve this by running
their decryptor in a safe environment, and placing a breakpoint on CryptImportKey with WinDbg -- dump
the key blob it receives to a file.

Usage:
```
pasta -e <.extext> -k <keyfile> [-f] <encryptedfile>
    -e  encrypted file extension (starting with '.' character
    -k  path to private key to use for decryption
    -f  force overwrite of existing decrypted file
    -h  show this help
```

For example,

`pasta -e .xyzxyz -k my_key.bin encrypted_file.xyzxyz`

If you like, you can easily run this on an entire directory with a quick batch script:

```for /c "C:\encrypted_dir" %x in (*.xyzxyz) do pasta.exe -k my_key.bin -e .xyzxyz "%x"```

This program has been tested on Windows 7 and 10, but it should port readily to other versions of Windows.

Good luck (and better luck next time...)

