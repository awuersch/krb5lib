open Sexplib.Std
open Asn.S

(* Always used as on optional field - only use if nonempty *)
type t = Host_address.t list [@@deriving sexp]

module Ast = struct
  type t = Host_address.Ast.t list

  let asn = sequence_of Host_address.Ast.asn
end

let ast_of_t t =
  match t with
  | [] -> failwith "Bug in ASN1 library: tried to use empty host_addresses"
  | lst -> List.map Host_address.ast_of_t lst

let t_of_ast = List.map Host_address.t_of_ast
