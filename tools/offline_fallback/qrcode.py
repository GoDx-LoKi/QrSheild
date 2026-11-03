"""Compatibility qrcode module backed by OpenCV QRCodeEncoder_create() and PIL."""
import cv2
import numpy as np
from PIL import Image

class QRCode:
    def __init__(self, version=None, error_correction=None, box_size=10, border=4):
        self.box_size = int(box_size)
        self.border = int(border)
        self._data = ""

    def add_data(self, data):
        self._data += str(data)

    def make(self, fit=True):
        pass

    def make_image(self, fill_color="black", back_color="white"):
        enc = cv2.QRCodeEncoder_create()
        mat = enc.encode(self._data or " ")
        padded = np.pad(mat, self.border, mode="constant", constant_values=255)
        scaled = np.repeat(np.repeat(padded, self.box_size, axis=0), self.box_size, axis=1)
        return Image.fromarray(scaled, mode="L")
