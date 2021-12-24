#-*- coding: utf-8 -*-

class CipherMode(object):
    lea = None
    no_more = False
    buffer = bytearray()

    def update(self, data):
        raise AssertionError('Only for reference')

    def encrypt(self, pt):
        ct = bytearray(16)
        raise AssertionError('Only for reference')

    def decrypt(self, ct):
        pt = bytearray(16)
        raise AssertionError('Only for reference')

    def final(self, *args, **kwargs):
        self.no_more = True
        return b''

class TagError(Exception):
    def __init__(self, message):
        super(TagError, self).__init__(message)