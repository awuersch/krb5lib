open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { lr_type : Krb_int32.t
  ; lr_value : Kerberos_time.t
  } [@@deriving sexp]

module Ast = struct
  type t = Krb_int32.Ast.t * Kerberos_time.Ast.t

  let asn =
    (sequence2
       (tag_required 0 ~label:"lr-type" Krb_int32.Ast.asn)
       (tag_required 1 ~label:"lr-value" Kerberos_time.Ast.asn))
end

let ast_of_t t =
  ( Krb_int32.ast_of_t t.lr_type
  , Kerberos_time.ast_of_t t.lr_value )

let t_of_ast (a, b) =
  { lr_type = Krb_int32.t_of_ast a
  ; lr_value = Kerberos_time.t_of_ast b
  }
