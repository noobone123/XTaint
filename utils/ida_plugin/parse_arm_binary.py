#!/usr/bin python
import sys
import os

from idc import *
from idautils import *
from idaapi import *

from struct import pack
from ctypes import c_uint32, c_uint64
import subprocess
from collections import defaultdict
import json

def get_all_functions():
    global segments

def init():
    base = get_imagebase()
    plt_start, plt_end = 0, 0
    segments = list(Segments())

    extern_seg = None
    extern_start = 0
    extern_end = 0
    text_seg = None
    text_start = 0
    text_end = 0
    plt_seg = None
    plt_start = 0
    plt_end = 0
    got_seg = None
    got_start = 0
    got_end = 0
    idata_seg = None
    idata_start = 0
    idata_end = 0
    data_seg = None
    data_start = 0
    data_end = 0
    vtable_sections = list()
    for segment in segments:
        if SegName(segment) == "extern":
            extern_seg = segment
            extern_start = SegStart(extern_seg)
            extern_end = SegEnd(extern_seg)
        elif SegName(segment) == ".text":
            text_seg = segment
            text_start = SegStart(text_seg)
            text_end = SegEnd(text_seg)
        elif SegName(segment) == ".plt":
            plt_seg = segment
            plt_start = SegStart(plt_seg)
            plt_end = SegEnd(plt_seg)
        elif SegName(segment) == ".got":
            got_seg = segment
            got_start = SegStart(got_seg)
            got_end = SegEnd(got_seg)
        elif SegName(segment) == ".idata":
            idata_seg = segment
            idata_start = SegStart(idata_seg)
            idata_end = SegEnd(idata_seg)
        elif SegName(segment) == ".data":
            data_seg = segment
            data_start = SegStart(data_seg)
            data_end = SegEnd(data_seg)
        elif SegName(segment) in vtable_section_names:
            vtable_sections.append(segment)

        sections = {}
        for segment in segments:
            name = SegName(segment)
            sections[name] = (SegStart(segment), SegEnd(segment))

        print(sections)

        if '.text' not in sections:
            print("Couldn't found text segment, should custom label!!!")

        if '.rodata' not in sections:
            print("Couldn't found rodata segment, should custom label!!!")

        if '.data' not in sections:
            print("Couldn't found data segment, should custom label!!!")

        if '.bss' not in sections:
            print("Couldn't found bss segment, should custom label!!!")

if __name__ == "__main__":
    # print into stdout
    # init()

    functions = get_all_functions()
    print(functions)
    
    # quit ida
    idaapi.auto_wait()