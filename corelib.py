"""
  Module: corelib.py
  Author: Hieu Nguyen (it.hieund@gmail.com), Nguyen Ton (nguyentonuno@gmail.com)
  Date: 2020-01-01
  Note: provide all util functions for secure message transfer and verify protocol
  References:
    - RSA: https://medium.com/asecuritysite-when-bob-met-alice/rsa-in-12-lines-of-python-799d07b3a5ea
    - AES: https://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
    - Hash: https://python.readthedocs.io/en/latest/library/hashlib.html
"""

import os, struct, random, libnum, json
from textwrap import wrap
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

__all__ = [
  'file_write_array', 'file_read_array', 'bytes_to_long', 'long_to_bytes', 
  'rsa_keygen', 'rsa_powermod', 'rsa_encrypt', 'rsa_decrypt',
  'aes_encrypt', 'aes_decrypt', 'sha_digest'
]

# Write array to file
def file_write_array(filename, array):
  try:
    with open(filename, 'w') as file:
      json.dump(array, file)
      return True
  except IOError:
    print("Can not write file")

# Read array from file
def file_read_array(filename):
  try:
    with open(filename,'r') as file:
      array = json.load(file)
      return array
  except IOError:
    print("File not accessible")

# Generate public key and private key for RSA
def rsa_keygen():
  bits = 100
  p = getPrime(bits)
  q = getPrime(bits)

  n = p * q
  PHI = (p - 1) * (q - 1)

  e = getPrime(bits)
  d = libnum.invmod(e, PHI)
  return ((e, n), (d, n))

# Power m with k and modulus by n for RSA encryption and decrytion
def rsa_powermod(m, k, n):
  c = pow(m, k, n)
  return c

# Encrypt text with RSA. The key can be either public or private key
def rsa_encrypt(text, keyarray):
    key, n = keyarray
    text_parts = wrap(text, 10)
    cipher = [rsa_powermod(bytes_to_long(part.encode('utf8')), key, n) for part in text_parts]
    return cipher

# Decrypt cipher with RSA. The key can be either public or private key
def rsa_decrypt(cipher, keyarray):
    try:
      key, n = keyarray
      text = [long_to_bytes(rsa_powermod(part, key, n)) for part in cipher]
      return b"".join(text).decode('utf8')
    except TypeError as e:
      print(e)

# Use AES with mode CBC to encrypt file
def aes_encrypt(key, in_filename, out_filename=None, chunksize=64*1024):
  if not out_filename:
    out_filename = in_filename + '.enc'

  iv = os.urandom(16)
  encryptor = AES.new(key, AES.MODE_CBC, iv)
  filesize = os.path.getsize(in_filename)

  with open(in_filename, 'rb') as infile:
    with open(out_filename, 'wb') as outfile:
      outfile.write(struct.pack('<Q', filesize))
      outfile.write(iv)

      while True:
        chunk = infile.read(chunksize)
        
        if len(chunk) == 0:
          break
        elif len(chunk) % 16 != 0:
          chunk += b' ' * (16 - len(chunk) % 16)

        outfile.write(encryptor.encrypt(chunk))

  return out_filename

# Use AES with mode CBC to decrypt file
def aes_decrypt(key, in_filename, out_filename=None, chunksize=24*1024):
  if not out_filename:
    out_filename = os.path.splitext(in_filename)[0]

  with open(in_filename, 'rb') as infile:
    origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
    iv = infile.read(16)
    decryptor = AES.new(key, AES.MODE_CBC, iv)

    with open(out_filename, 'wb') as outfile:
      while True:
        chunk = infile.read(chunksize)

        if len(chunk) == 0:
          break

        outfile.write(decryptor.decrypt(chunk))

      outfile.truncate(origsize)

  return out_filename

# Use SHA256 to digest a string
def sha_digest(string):
  h = SHA256.new()
  h.update(string)
  digest = h.hexdigest()
  return digest