#!/usr/bin/env python3
"""
Show MobaXterm stored credentials and passwords.

Supported storage flavours:
  * legacy session-based obfuscation      -> MobaXterm < 20.x
  * MobaXterm 20.x .. 26.x (master password mode). The master key is stored
    in HKCU\\Software\\Mobatek\\MobaXterm\\M protected with DPAPI (entropy =
    the "SessionP" value), so the script has to run under the same Windows
    user on the same machine.
    Values are AES-256-CFB8 ciphertexts; since version 25 they are stored as
    "_@" + 18-character salt + base64(ciphertext).

Usage:
    python ShowMobaXterm.py                       automatic mode
    python ShowMobaXterm.py <master_password>     force a master password
    python ShowMobaXterm.py --raw                 also dump stored values
"""
import base64
import ctypes
import itertools
import os
import platform
import random
import sys
import winreg
from ctypes import wintypes

try:
    from Crypto.Hash import SHA512
    from Crypto.Cipher import AES
except ImportError:
    sys.exit(
        "Missing dependency: pycryptodome.\n"
        "Install it with:\n"
        "    python -m pip install pycryptodome"
    )

if platform.system().lower() != 'windows':
    print('Please run this script in Windows.')
    exit(-1)

try:                                    # print Russian/Unicode text correctly
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except (AttributeError, ValueError):
    pass

REG_BASE = r'Software\Mobatek\MobaXterm'
# DPAPI blob header (version + provider GUID) that MobaXterm strips from the "M" value
DPAPI_HEADER = bytes.fromhex('01000000d08c9ddf0115d1118c7a00c04fc297eb')
NEW_FORMAT_MARKER = '_@'                # prefix used by MobaXterm 25/26
SALT_LENGTH = 18                        # random salt length in the v25/26 format
B64_ALPHABET = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/'
_B64_CHARS = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')


class NewFormatError(Exception):
    """The stored value was written by a MobaXterm version we cannot read."""


def _current_user() -> str:
    """os.getlogin() raises OSError when there is no console; fall back to env."""
    try:
        return os.getlogin()
    except OSError:
        return os.environ.get('USERNAME') or os.environ.get('USER') or ''


def _encode_ansi(text: str) -> bytes:
    """Encode a string the way MobaXterm stores it (Windows ANSI code page)."""
    for encoding in ('mbcs', 'cp1251', 'utf-8'):
        try:
            return text.encode(encoding)
        except (LookupError, UnicodeEncodeError):
            continue
    return text.encode('utf-8', 'replace')


def _decode_password(data: bytes) -> str:
    """Decode decrypted password bytes into text."""
    data = data.split(b'\x00', 1)[0]
    for encoding in ('utf-8', 'mbcs'):
        try:
            return data.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode('cp1251', 'replace')


def _b64decode(text: str) -> bytes:
    """Decode a base64 value, restoring the padding MobaXterm may have dropped."""
    text = text.strip()
    if not text:
        raise ValueError('empty value')
    for char in text.rstrip('='):
        if char not in _B64_CHARS:
            raise NewFormatError(text)
    text += '=' * (-len(text) % 4)
    return base64.b64decode(text)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for byte in data if 32 <= byte < 127 or byte in (9, 10, 13))
    return good / len(data)


def WinRegistryReadValue(Root, SubKey: str, ValueName: str, ExpectValueType: int = None):
    Key = winreg.OpenKey(Root, SubKey)
    Value, ValueType = winreg.QueryValueEx(Key, ValueName)
    if type(ExpectValueType) == int and ValueType != ExpectValueType:
        raise TypeError('Expect %d, but %d is given.' % (ExpectValueType, ValueType))
    return Value
class MobaXtermCrypto:
    """Legacy (session-based) MobaXterm obfuscation, MobaXterm < 20.x."""

    def __init__(self, SysHostname: bytes, SysUsername: bytes, SessionP: bytes = None):
        self._SysHostname = SysHostname
        self._SysUsername = SysUsername
        self._SessionP = SessionP

    def _KeyCrafter(self, **kargs) -> bytes:
        if kargs.get('ConnHostname') != None and kargs.get('ConnUsername') != None:
            s1 = self._SysUsername + self._SysHostname
            while len(s1) < 20:
                s1 = s1 + s1

            s2 = kargs.get('ConnUsername') + kargs.get('ConnHostname')
            while len(s2) < 20:
                s2 = s2 + s2

            key_space = [
                s1.upper(),
                s2.upper(),
                s1.lower(),
                s2.lower()
            ]
        else:
            s = self._SessionP
            while len(s) < 20:
                s = s + s

            key_space = [
                s.upper(),
                s.upper(),
                s.lower(),
                s.lower()
            ]

        key = bytearray(b'0d5e9n1348/U2+67')
        for i in range(0, len(key)):
            b = key_space[(i + 1) % len(key_space)][i]
            if (b not in key) and (b in B64_ALPHABET):
                key[i] = b

        return bytes(key)

    def EncryptPassword(self, Plaintext: bytes, ConnHostname: bytes, ConnUsername: bytes) -> str:
        key = self._KeyCrafter(ConnHostname=ConnHostname, ConnUsername=ConnUsername)

        ct = bytearray()
        for char in Plaintext:
            ct.append(key[char & 0x0f])
            key = key[-1:] + key[0:-1]

            ct.append(key[char >> 4])
            key = key[-1:] + key[0:-1]

        Ciphertext = bytearray()
        obfuscate_chars = bytes(filter(lambda char: char not in key, B64_ALPHABET))
        for char in ct:
            while random.choice([True, False, False]) == False:
                Ciphertext.append(random.choice(obfuscate_chars))
            Ciphertext.append(char)
        while random.choice([True, False, False]) == False:
            Ciphertext.append(random.choice(obfuscate_chars))

        return Ciphertext.decode()

    def EncryptCredential(self, Plaintext: bytes) -> str:
        key = self._KeyCrafter()

        ct = bytearray()
        for char in Plaintext:
            ct.append(key[char & 0x0f])
            key = key[-1:] + key[0:-1]

            ct.append(key[char >> 4])
            key = key[-1:] + key[0:-1]

        Ciphertext = bytearray()
        obfuscate_chars = bytes(filter(lambda char: char not in key, B64_ALPHABET))
        for char in ct:
            while random.choice([True, False, False]) == False:
                Ciphertext.append(random.choice(obfuscate_chars))
            Ciphertext.append(char)
        while random.choice([True, False, False]) == False:
            Ciphertext.append(random.choice(obfuscate_chars))

        return Ciphertext.decode()

    @staticmethod
    def _Deobfuscate(Ciphertext: str, key: bytes) -> bytes:
        if Ciphertext.startswith(NEW_FORMAT_MARKER):
            raise NewFormatError(Ciphertext)

        ct = bytearray()
        for char in Ciphertext.encode('ascii', 'replace'):
            if char in key:
                ct.append(char)

        if len(ct) % 2 != 0:
            raise ValueError('Invalid ciphertext (odd number of key characters).')

        pt = bytearray()
        for i in range(0, len(ct), 2):
            l = key.find(ct[i])
            key = key[-1:] + key[0:-1]
            h = key.find(ct[i + 1])
            key = key[-1:] + key[0:-1]
            if l < 0 or h < 0:
                raise ValueError('Invalid ciphertext (unknown key character).')
            pt.append(16 * h + l)
        return bytes(pt)

    def DecryptPassword(self, Ciphertext: str, ConnHostname: bytes, ConnUsername: bytes) -> bytes:
        key = self._KeyCrafter(ConnHostname=ConnHostname, ConnUsername=ConnUsername)
        return self._Deobfuscate(Ciphertext, key)

    def DecryptCredential(self, Ciphertext: str) -> bytes:
        key = self._KeyCrafter()
        return self._Deobfuscate(Ciphertext, key)


class MobaXtermCryptoSafe:
    """Master-password mode: AES-256-CFB8.

    Two storage layouts are handled:
      * MobaXterm 20.x .. 24.x: value == base64(ciphertext), IV = AES-ECB(0)
      * MobaXterm 25.x/26.x    : value == "_@" + 18-char salt + base64(ciphertext),
                                 IV = first 16 salt characters
    """

    def __init__(self, Key: bytes):
        self._Key = bytes(Key)[0:32]

    @classmethod
    def FromMasterPassword(cls, MasterPassword: str) -> 'MobaXtermCryptoSafe':
        return cls(SHA512.new(_encode_ansi(MasterPassword)).digest()[0:32])

    def _Cipher(self, iv: bytes):
        return AES.new(key=self._Key, iv=iv, mode=AES.MODE_CFB, segment_size=8)

    def DecryptPassword(self, Ciphertext: str) -> bytes:
        if Ciphertext.startswith(NEW_FORMAT_MARKER):
            salt = Ciphertext[2:2 + SALT_LENGTH]
            if len(salt) != SALT_LENGTH:
                raise NewFormatError(Ciphertext)
            ciphertext = _b64decode(Ciphertext[2 + SALT_LENGTH:])
            iv = (salt.encode('ascii') * 16)[:AES.block_size]
            return self._Cipher(iv).decrypt(ciphertext)

        data = _b64decode(Ciphertext)
        iv = AES.new(key=self._Key, mode=AES.MODE_ECB).encrypt(b'\x00' * AES.block_size)
        return self._Cipher(iv).decrypt(data)

    def DecryptCredential(self, Ciphertext: str) -> bytes:
        return self.DecryptPassword(Ciphertext)


class _DataBlob(ctypes.Structure):
    _fields_ = [('cbData', wintypes.DWORD),
                ('pbData', ctypes.POINTER(ctypes.c_char))]


_crypt32 = ctypes.WinDLL('crypt32', use_last_error=True)
_kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)


def _make_blob(data: bytes):
    buffer = ctypes.create_string_buffer(data, len(data))
    blob = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    return blob, buffer


def DpapiUnprotect(data: bytes, Entropy: bytes = None) -> bytes:
    """Windows DPAPI CryptUnprotectData (current user scope)."""
    data_in, keep_data = _make_blob(data)
    if Entropy:
        entropy, keep_entropy = _make_blob(Entropy)
        entropy_ptr = ctypes.byref(entropy)
    else:
        entropy_ptr = None

    data_out = _DataBlob()
    if not _crypt32.CryptUnprotectData(ctypes.byref(data_in), None, entropy_ptr, None, None, 0,
                                       ctypes.byref(data_out)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(data_out.pbData, data_out.cbData)
    finally:
        _kernel32.LocalFree(data_out.pbData)


def ReadSessionP() -> str:
    return WinRegistryReadValue(winreg.HKEY_CURRENT_USER, REG_BASE, 'SessionP', winreg.REG_SZ)


def ReadMasterKey(SessionP: str):
    """Return the AES key used by master-password mode, or None if not available."""
    try:
        Key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_BASE + r'\M')
    except FileNotFoundError:
        return None

    ValueName = '%s@%s' % (_current_user(), platform.node())
    try:
        Value = winreg.QueryValueEx(Key, ValueName)[0]
    except FileNotFoundError:
        # MobaXterm stores the value under "<user>@<computer>"; fall back to the
        # first value in case the computer or the user name has been changed.
        try:
            Value = winreg.EnumValue(Key, 0)[1]
        except OSError:
            return None

    try:
        Blob = base64.b64decode(Value + '=' * (-len(Value) % 4))
        HashBase64 = DpapiUnprotect(DPAPI_HEADER + Blob, _encode_ansi(SessionP))
        Digest = base64.b64decode(HashBase64)
    except Exception:
        return None

    if len(Digest) < 32:
        return None
    return Digest[0:32]
_new_format_reported = False


def _ReportNewFormat():
    global _new_format_reported
    if _new_format_reported:
        print('  [!] Не удалось расшифровать значение (неизвестный формат).')
        return
    _new_format_reported = True
    print('  [!] Не удалось расшифровать значение: неизвестный формат хранения.')
    print('      Обычные причины:')
    print('      - скрипт запущен не под тем пользователем/компьютером, где')
    print('        сохранён мастер-пароль (ключ защищён DPAPI);')
    print('      - в MobaXterm задан новый мастер-пароль после записи значений.')
    print('      Можно посмотреть пароли в самой MobaXterm:')
    print('      Настройки -> Общие -> "MobaXterm passwords management"')
    print('      -> "Show passwords" / "Export to file"')


def _DecryptOrReport(DecryptFunction, *args, raw=None):
    """Return plaintext bytes or None; prints the reason when decryption fails."""
    if raw is not None:
        print('[*] Stored:   %s' % raw)
    try:
        Plaintext = DecryptFunction(*args)
    except NewFormatError:
        _ReportNewFormat()
        print('')
        return None
    except Exception as error:
        print('[*] Password: <не удалось расшифровать: %s>' % error)
        print('')
        return None

    if _printable_ratio(Plaintext) < 0.85:
        print('[*] Password: <не удалось расшифровать: результат не похож на текст>')
        print('')
        return None
    return Plaintext


def DumpCredentials(cipher, raw: bool = False):
    try:
        Key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_BASE + r'\C')
    except FileNotFoundError:
        return

    print('Credentials'.center(48, '-'))

    for i in itertools.count(0):
        try:
            ValueName, Value, ValueType = winreg.EnumValue(Key, i)
        except OSError:
            break
        if ValueType != winreg.REG_SZ:
            continue

        CredentialUsername, _, CredentialPassword = Value.partition(':')
        print('[*] Name:     %s' % ValueName)
        print('[*] Username: %s' % CredentialUsername)

        Plaintext = _DecryptOrReport(
            cipher.DecryptCredential, CredentialPassword,
            raw=CredentialPassword if raw else None
        )
        if Plaintext is not None:
            print('[*] Password: %s' % _decode_password(Plaintext))
            print('')


def DumpPasswords(cipher, raw: bool = False):
    try:
        Key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_BASE + r'\P')
    except FileNotFoundError:
        return

    print('Passwords'.center(48, '-'))

    for i in itertools.count(0):
        try:
            ValueName, Value, ValueType = winreg.EnumValue(Key, i)
        except OSError:
            break
        if ValueType != winreg.REG_SZ:
            continue

        print('[*] Name:     %s' % ValueName)

        if isinstance(cipher, MobaXtermCrypto):
            ConnUsername, ConnHostname = ValueName.split('@')
            if ':' in ConnUsername:
                ConnUsername = ConnUsername.split(':')[-1]
            DecryptFunction = cipher.DecryptPassword
            DecryptArgs = (Value, _encode_ansi(ConnHostname), _encode_ansi(ConnUsername))
        else:
            DecryptFunction = cipher.DecryptPassword
            DecryptArgs = (Value,)

        Plaintext = _DecryptOrReport(
            DecryptFunction, *DecryptArgs,
            raw=Value if raw else None
        )
        if Plaintext is not None:
            print('[*] Password: %s' % _decode_password(Plaintext))
            print('')


def main(argv) -> int:
    raw = '--raw' in argv
    args = [arg for arg in argv if not arg.startswith('--')]

    if args:
        cipher = MobaXtermCryptoSafe.FromMasterPassword(args[0])
        SessionP = None
    else:
        SessionP = ReadSessionP()
        MasterKey = ReadMasterKey(SessionP)
        if MasterKey:
            cipher = MobaXtermCryptoSafe(MasterKey)
        else:
            cipher = MobaXtermCrypto(platform.node().encode('mbcs', 'replace'),
                                     _current_user().encode('mbcs', 'replace'),
                                     _encode_ansi(SessionP))

    try:
        DumpCredentials(cipher, raw)
    except Exception as error:
        print('Credentials: %s' % error)

    try:
        DumpPasswords(cipher, raw)
    except Exception as error:
        print('Passwords: %s' % error)

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))