open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { etype : Krb_int32.t
  ; salt : Kerberos_string.t option
  ; s2kparams : Octet_string.t option
  } [@@deriving sexp]

module Ast = struct
  type t =
      Krb_int32.Ast.t
    * Kerberos_string.Ast.t option
    * Octet_string.Ast.t option

  let asn =
    (sequence3
       (tag_required 0 ~label:"etype" Krb_int32.Ast.asn)
       (tag_optional 1 ~label:"salt" Kerberos_string.Ast.asn)
       (tag_optional 2 ~label:"s2kparams" Octet_string.Ast.asn))
end

let ast_of_t t =
  ( Krb_int32.ast_of_t t.etype
  , Option.map ~f:Kerberos_string.ast_of_t t.salt
  , Option.map ~f:Octet_string.ast_of_t t.s2kparams )

let t_of_ast (a, b, c) =
  { etype = Krb_int32.t_of_ast a
  ; salt = Option.map ~f:Kerberos_string.t_of_ast b
  ; s2kparams = Option.map ~f:Octet_string.t_of_ast c
  }
