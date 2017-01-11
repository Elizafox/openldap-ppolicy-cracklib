openldap-ppolicy-cracklib
=========================

This is a password policy module for OpenLDAP that uses CrackLib.

It also includes additional checks inspired by the `VeryFascistCheck` function in Python's cracklib wrapper.

Usage
=====

Ensure `pwdPolicy` is an objectClass of your password policy schema, then set the
attribute `pwdCheckModule` to whatever you compile this module as.

The module should go in your distribution's path for OpenLDAP modules.

Building
========

If your distribution provides the slap.h header, you're golden. Otherwise, fetch
the OpenLDAP source (`apt-get source slapd` or such), configure and build it with
`./configure` and `make`, then use the following incantation:

```bash
OPENLDAP_SOURCE=/path/to/source
gcc ppolicy-cracklib.c -o ppolicy-cracklib.so \
-std=c99 -shared -lcrack -llber -lldap_r\
-I${OPENLDAP_SOURCE}/include \
-I${OPENLDAP_SOURCE}/libraries \
-I${OPENLDAP_SOURCE}/libraries/libldap \
-I${OPENLDAP_SOURCE}/servers/slapd
```

On Debian, it may be easier to fetch the source package and run `debuild -b`
first (you can ctrl-c the test phase); you will have to add
`-I${OPENLDAP_SOURCE}/debian/build/include` due to Debian silliness.
