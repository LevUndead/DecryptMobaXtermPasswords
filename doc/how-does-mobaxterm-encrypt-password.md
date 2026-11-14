# How does MobaXterm encrypt password?

MobaXterm keeps credentials in
`HKEY_CURRENT_USER\Software\Mobatek\MobaXterm\C` (credential names) and
`HKEY_CURRENT_USER\Software\Mobatek\MobaXterm\P` (session passwords).
Up to version 24 the values are obfuscated / encrypted with a key derived
from `SessionP` or from the master password; since version 25 the master
password layout changed.

## Master password hash

When a master password is set, MobaXterm stores `SHA512(master password)`
in `HKCU\Software\Mobatek\MobaXterm\M`, under the value name
`<user>@<computer>`:

1. the value is base64; after decoding, the 20-byte DPAPI header
   (`01 00 00 00` + provider GUID `d08c9ddf-0115-11d1-8c7a-00c04fc297eb`)
   has been stripped off, so it has to be prepended again;
2. `CryptUnprotectData(blob, entropy = SessionP)` returns the base64 text of
   the SHA512 digest;
3. the AES key is the first 32 bytes of that digest.

## Value layouts

| Version | Value | Cipher |
| --- | --- | --- |
| < 20.x | printable characters, two per plaintext byte plus random padding characters | nibble obfuscation with a 16-character key built from `0d5e9n1348/U2+67`, `SessionP` and `<user>@<host>` |
| 20.x - 24.x | `base64(ciphertext)` | AES-256-CFB8, `IV = AES-ECB(key, 0)` |
| 25.x - 26.x | `"_@" + salt + base64(ciphertext)` | AES-256-CFB8, `IV = first 16 characters of salt` |

The salt of the 25.x/26.x layout is 18 characters taken from the alphabet
`0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/`; it is
random for every stored value, so the same password produces different
ciphertexts. The base64 part may be stored without its `=` padding and its
length equals the plaintext length (CFB is a stream mode).

## Notes

* DPAPI binds the master key to the Windows account, therefore the key can
  only be recovered by the user who created it, on the same machine.
* With a personal edition MobaXterm stores the master password hash this way
  by default (`WhenToPromptForMasterPassword=0`), so no interaction is
  needed to read the values.
* Passwords can also be exported from MobaXterm itself:
  *Settings -> General -> "MobaXterm passwords management" ->
  "Show passwords" / "Export to file"*.

