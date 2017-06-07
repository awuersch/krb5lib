(*---------------------------------------------------------------------------
   Copyright (c) 2017 Tony Wuersch. All rights reserved.
   Copyright (c) 2015 Brandon Bohrer. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
   %%NAME%% %%VERSION%%
  ---------------------------------------------------------------------------*)

open Sexplib
open Asn.S

let all_types = Types.all

let count_occurrences lst x =
  List.length (List.filter (fun y -> x = y) lst)

let run () =
  let () = Random.init 63 in
  let encoding_rules = [Asn.ber; Asn.der] in
  let results =
    List.map (fun (name,tp) ->
      let module Type = (val tp : Asn1_intf.S) in
      let asn = Type.Ast.asn in
      let codecs = List.map (fun er -> Asn.codec er asn) encoding_rules in
      let input = Asn.random asn in
      Printf.printf "%s\n" name;
      let s =
        try Type.t_of_ast input |> Type.sexp_of_t |> (Sexp.to_string_hum ~indent:2) with
        | Not_found -> "not_found"
        | Failure errstr -> "Failure: " ^ errstr
      in
      Printf.printf "%s\n" s;
      let test_results =
        List.map (fun codec ->
          match Asn.decode codec (Asn.encode codec input) with
          | Ok (ast, _) -> ast = input
          | Error err -> error err)
          codecs
      in
      List.for_all (fun x -> x) test_results)
      all_types
  in
  Printf.printf "%d tests run, %d succeeded, %d failed\n"
    (List.length all_types)
    (count_occurrences results true)
    (count_occurrences results false)

let () = run ()

(*---------------------------------------------------------------------------
   Copyright (c) 2017 Tony Wuersch
   Copyright (c) 2015 Brandon Bohrer

   Permission to use, copy, modify, and/or distribute this software for any
   purpose with or without fee is hereby granted, provided that the above
   copyright notice and this permission notice appear in all copies.

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
  ---------------------------------------------------------------------------*)
