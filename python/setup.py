#!/usr/bin/env python

from distutils.core import setup, Extension
import subprocess
import os

def pkgconfig(what):
    out = []
    cmd = 'pkg-config %s %s' % (what, 'rpm')
    pcout = subprocess.check_output(cmd.split()).decode()
    for token in pcout.split():
        out.append(token[2:])
    return out

cflags = ['-std=c99', '-Wno-strict-aliasing']
additional_link_args = []

# See if we're building in-tree
if os.access('Makefile.am', os.F_OK):
    cflags.append('-I../include')
    additional_link_args.extend(['-Wl,-L../rpmio/.libs',
                                 '-Wl,-L../lib/.libs',
                                 '-Wl,-L../build/.libs',
                                 '-Wl,-L../sign/.libs'])
    os.environ['PKG_CONFIG_PATH'] = '..'


rpmmod = Extension('rpm._rpm',
                   sources = [  'header-py.c', 'rpmds-py.c', 'rpmfd-py.c',
				'rpmfi-py.c', 'rpmii-py.c', 'rpmkeyring-py.c',
                                'rpmmacro-py.c', 'rpmmi-py.c', 'rpmps-py.c',
                                'rpmstrpool-py.c', 'rpmfiles-py.c', 
				'rpmarchive-py.c', 'rpmtd-py.c',
                                'rpmte-py.c', 'rpmts-py.c', 'rpmmodule.c',
                             ],
                   include_dirs = pkgconfig('--cflags'),
                   library_dirs = pkgconfig('--libs-only-L'),
                   libraries = pkgconfig('--libs-only-l'),
                   extra_compile_args = cflags,
                   extra_link_args = additional_link_args
                  )

rpmbuild_mod = Extension('rpm._rpmb',
                   sources = ['rpmbmodule.c', 'spec-py.c'],
                   include_dirs = pkgconfig('--cflags'),
                   library_dirs = pkgconfig('--libs-only-L'),
                   libraries = pkgconfig('--libs-only-l') + ['rpmbuild'],
                   extra_compile_args = cflags,
                   extra_link_args = additional_link_args
                  )

rpmsign_mod = Extension('rpm._rpms',
                   sources = ['rpmsmodule.c'],
                   include_dirs = pkgconfig('--cflags'),
                   library_dirs = pkgconfig('--libs-only-L'),
                   libraries = pkgconfig('--libs-only-l') + ['rpmsign'],
                   extra_compile_args = cflags,
                   extra_link_args = additional_link_args
                  )

setup(name='rpm',
      version='4.14.2.1',
      description='Python bindings for rpm',
      maintainer_email='rpm-maint@lists.rpm.org',
      url='http://www.rpm.org/',
      packages = ['rpm'],
      ext_modules= [rpmmod, rpmbuild_mod, rpmsign_mod]
     )
