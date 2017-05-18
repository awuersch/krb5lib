open Sexplib.Std
open Asn.S
open Krb_combinators

type t = Last_req_inst.t list [@@deriving sexp]

module Ast = struct
  type t = Last_req_inst.Ast.t list

  let asn = sequence_of Last_req_inst.Ast.asn
end

let ast_of_t t =
  match t with
  | [] -> failwith "Bug in ASN1 library: tried to use empty host_addresses"
  | lst -> List.map Last_req_inst.ast_of_t lst

let t_of_ast = List.map Last_req_inst.t_of_ast
