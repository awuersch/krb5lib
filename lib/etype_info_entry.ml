open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { etype : Krb_int32.t
  ; salt : Octet_string.t option
  } [@@deriving sexp]

module Ast = struct
  type t = Krb_int32.Ast.t * Octet_string.Ast.t option

  let asn =
    (sequence2
       (tag_required 0 ~label:"etype" Krb_int32.Ast.asn)
       (tag_optional 1 ~label:"salt" Octet_string.Ast.asn))
end

let ast_of_t t =
  ( Krb_int32.ast_of_t t.etype
  , Option.map ~f:Octet_string.ast_of_t t.salt )

let t_of_ast (a, b) =
  { etype = Krb_int32.t_of_ast a
  ; salt = Option.map ~f:Octet_string.t_of_ast b
  }
