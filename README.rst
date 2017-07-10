tinfoildb
=========

TinfoilDB is an database model that allows fast storage and retrieval of secret values under a master key. Retrieved values are tamper-evident, and master keys can be variably strengthened where allowed by hardware.

This package provides an implementation of TinfoilDB as a daily-use password manager. Weak passwords are vulnerable to attack, and strong passwords are hard to remember. Tinfoil solves the "password problem" by enabling usage of highly secure passwords without having to actually remember them.

Installation
~~~~~~~~~~~~
::

    pip install tinfoildb

Usage
~~~~~
::

   tinfoil

The first time you run tinfoil, you will need to set up the basic parameters for your database. By default, your database will exist in your local directory, under the filename *tinfoil.db*.
