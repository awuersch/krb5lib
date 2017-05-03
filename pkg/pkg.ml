#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  Pkg.describe "krb5lib" @@ fun c ->
  Ok [ Pkg.mllib "lib/krb5lib.mllib";
       Pkg.test "test/test"; ]
