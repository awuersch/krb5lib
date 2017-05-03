krb5lib — Kerberos5 msgs and syntaxes as records and types.
-------------------------------------------------------------------------------
%%VERSION%%

krb5lib is TODO

krb5lib is distributed under the ISC license.

Homepage: https://github.com/awuersch/krb5lib  

## Installation

krb5lib cannot yet be installed with `opam`:

    opam install krb5lib

If you don't use `opam` consult the [`opam`](opam) file for build
instructions.

## Documentation

The documentation and API reference will be generated from source
interfaces. It will be able to be consulted [online][doc] or via `odig doc
krb5lib`.

[doc]: https://tony.wuersch.name/krb5lib/doc

## Sample programs

If you installed krb5lib with `opam` sample programs are located in
the directory `opam var krb5lib:doc`.

In the distribution sample programs and tests are located in the
[`test`](test) directory. They can be built and run
with:

    topkg build --tests true && topkg test 
