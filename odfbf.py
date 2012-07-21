#!/usr/bin/env python2

"""Program to check a password against encrypted ODF files.
Inspired by http://ringlord.com/odfjlib.html and oodecr."""

from xml.etree.ElementTree import ElementTree
from Crypto.Cipher import Blowfish
from Crypto.Cipher import AES
import zipfile
import sys
import base64
import hashlib
import pbkdf2

if __name__ == "__main__":

    if len(sys.argv) < 3:
        print >> sys.stderr, "Usage: %s <ODF file> <password>" % sys.argv[0]
        sys.exit(1)
    try:
        zf = zipfile.ZipFile(sys.argv[1])
    except zipfile.BadZipfile:
        print >> sys.stderr, "%s is not an OpenOffice file!" % sys.argv[1]
        sys.exit(2)

    password = sys.argv[2]

    try:
        mf = zf.open("META-INF/manifest.xml")
    except KeyError, exc:
        print >> sys.stderr, "%s is not an OpenOffice file!" % sys.argv[1]
        sys.exit(3)

    tree = ElementTree()
    tree.parse(mf)
    r = tree.getroot()
    elements = list(r.iter())

    is_encrypted = False
    key_size = 16
    for i in range(0, len(elements)):
        element = elements[i]
        if element.get("{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}full-path") == "content.xml":
            for j in range(i + 1, i + 1 + 3):
                element = elements[j]
                # print element.items()
                data = element.get("{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}checksum")
                if data:
                    is_encrypted = True
                    checksum = data
                data = element.get("{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}checksum-type")
                if data:
                    checksum_type = data
                data = element.get("{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}initialisation-vector")
                if data:
                    iv = data
                data = element.get("{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}salt")
                if data:
                    salt = data
                data = element.get("{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}algorithm-name")
                if data:
                    algorithm_name = data
                data = element.get("{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}iteration-count")
                if data:
                    iteration_count = data
                data = element.get("{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}key-size")
                if data:
                    key_size = data

    if not is_encrypted:
        print >> sys.stderr, "%s is not an encrypted OpenOffice file!" % sys.argv[1]
        sys.exit(4)

    # print checksum, iv, salt, checksum_type, algorithm_name, iteration_count
    checksum = base64.decodestring(checksum)
    iv = base64.decodestring(iv)
    salt = base64.decodestring(salt)
    try:
        content = zf.open("content.xml").read()
    except KeyError, exc:
        print >> sys.stderr, "%s is not an encrypted OpenOffice file, content.xml missing!" % sys.argv[1]
        sys.exit(5)

    if algorithm_name.find("Blowfish CFB") > -1:
        pwdHash = hashlib.sha1(password).digest()
        key = pbkdf2.pbkdf(pwdHash, salt, int(iteration_count), int(key_size))
        bf = Blowfish.new(key=key, mode=Blowfish.MODE_CFB, IV=iv, segment_size=64)
        pt = bf.decrypt(content[0:1024])

    elif algorithm_name.find("aes256-cbc") > -1:
        pwdHash = hashlib.sha256(password).digest()
        key = pbkdf2.pbkdf(pwdHash, salt, int(iteration_count), int(key_size))
        aes = AES.new(key=key, mode=AES.MODE_CBC, IV=iv)
        pt = aes.decrypt(content)
    else:
        print >> sys.stderr, "%s uses un-supported encryption!" % sys.argv[1]
        sys.exit(6)

    if checksum_type.find("SHA1") > -1:
        cchecksum = hashlib.sha1(pt[0:1024]).digest()
    else:
        cchecksum = hashlib.sha256(pt[0:1024]).digest()

    if cchecksum == checksum:
        print "Right Password!"
        sys.exit(0)
    else:
        print "Wrong Password!"
        sys.exit(7)
