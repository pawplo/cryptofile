# cryptofile aes-256-cbc mode encryption/decryption file

Random initialization vector (iv).

Randon padding data.

usage: `cryptofile {enc | dec} <key> <in_file> <out_file>`

`<key>`    256 bit key in 64 bytes hex format.

To generate key you can use hard time and memory key derivation function such as argon2:

    echo -n "some-strong-password" | argon2 some-salt -t 20 -m 20 -r > ./key.txt

Then encrypt:

    cryptofile enc `cat ./key.txt` somefile.txt somefile.txt.enc

And decrypt:

    cryptofile dec `cat ./key.txt` somefile.txt.enc somefile.txt.enc.dec

Then `somefile.txt` and `somefile.txt.enc.dec` should be the same.

PS: When you use argon2 to generate key from password remeber to remeber ;)
or save not only password but salt and other parameters too.

github.com/pawplo/cryptofile

aes.c and aes.h files from [github.com/kokke/tiny-AES-c](https://github.com/kokke/tiny-AES-c)
