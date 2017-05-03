open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { addr_type : Address_type.t
  ; address : Octet_string.t
  } [@@deriving sexp]

module Ast = struct
  type t = Address_type.Ast.t * Cstruct.t

  let asn =
    (sequence2
       (tag_required 0 ~label:"addr_type" Address_type.Ast.asn)
       (tag_required 1 ~label:"address" Octet_string.Ast.asn))
end

let ast_of_t t =
  ( Address_type.ast_of_t t.addr_type
  , Octet_string.ast_of_t t.address )

let t_of_ast (a, b) =
  { addr_type = Address_type.t_of_ast a
  ; address = Octet_string.t_of_ast b
  }
