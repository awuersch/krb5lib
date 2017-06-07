open Sexplib.Std
open Asn.S

type t = Etype_info_entry.t list [@@deriving sexp]

module Ast = struct
  type t = Etype_info_entry.Ast.t list

  let asn = sequence_of Etype_info_entry.Ast.asn
end

let ast_of_t t =
  match t with
  | [] -> failwith "Bug in ASN1 library: tried to use empty typed data"
  | lst -> List.map Etype_info_entry.ast_of_t lst

let t_of_ast = List.map Etype_info_entry.t_of_ast
