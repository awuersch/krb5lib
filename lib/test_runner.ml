open Sexplib
open Std
open Asn.S
open Krb_combinators

let all_types = Types.one

let count_occurrences lst x =
  List.length (List.filter (fun y -> x = y) lst)

let run () =
  let encoding_rules = [Asn.ber; Asn.der] in
  let results =
    List.map (fun tp ->
      let module Type = (val tp : Asn1_intf.S) in
      let asn = Type.Ast.asn in
      let codecs = List.map (fun er -> Asn.codec er asn) encoding_rules in
      let input = Asn.random asn in
      (* let s = Type.t_of_ast input |> Type.sexp_of_t |> Sexp.to_string in
      Printf.printf "sexp: %s" s; *)
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
