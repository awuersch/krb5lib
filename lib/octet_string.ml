(* CR bbohrer: replace all octet_string's with this*)

open Sexplib.Std
open Asn.S

type t = string [@@deriving sexp]

module Ast = struct
  type t = Cstruct.t

  let asn = octet_string
end

let ast_of_t : t -> Ast.t = Cstruct.of_string ~allocator:Cstruct.create

let t_of_ast : Ast.t -> t = Cstruct.to_string
