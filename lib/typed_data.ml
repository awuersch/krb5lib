open Sexplib.Std
open Asn.S
open Krb_combinators

type t = Typed_datum.t list [@@deriving sexp]

module Ast = struct
  type t = Typed_datum.Ast.t list

  let asn = sequence_of Typed_datum.Ast.asn
end

let ast_of_t t =
  match t with
  | [] -> failwith "Bug in ASN1 library: tried to use empty typed data"
  | lst -> List.map Typed_datum.ast_of_t lst

let t_of_ast = List.map Typed_datum.t_of_ast
