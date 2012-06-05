#!/usr/bin/env python2

"""Program to check a password against encrypted ODF files.
Inspired by http://ringlord.com/odfjlib.html and oodecr."""

import xml.etree.ElementTree
import zipfile
import sys
import base64
import binascii
import hashlib
import pbkdf2
import zlib

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

    from xml.etree.ElementTree import ElementTree
    tree = ElementTree()
    tree.parse(mf)
    r = tree.getroot()
    elements = list(r.iter())

    is_encrypted = False
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

    pwdHash = hashlib.sha1(password).digest()
    key = pbkdf2.pbkdf(pwdHash, salt, 1024, 16)
    from Crypto.Cipher import Blowfish
    bf = Blowfish.new(key=key, mode=Blowfish.MODE_CFB, IV=iv, segment_size=64)
    pt = bf.decrypt(content)
    cchecksum = hashlib.sha1(pt[0:1024]).digest()
    if cchecksum == checksum:
        # inflate pt
        try:
            ipt = zlib.decompress(pt, -15)
        except:
            print "Can't inflate, Wrong Password?"
            sys.exit(6)
        print "Right Password!"
        sys.exit(0)
    else:
        print "Wrong Password!"
        sys.exit(7)


