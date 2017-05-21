open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { data_type : Krb_int32.t
  ; data_value : Octet_string.t option
  } [@@deriving sexp]

module Ast = struct
  type t = Krb_int32.Ast.t * Octet_string.Ast.t option

  let asn =
    (sequence2
       (tag_required 0 ~label:"data-type" Krb_int32.Ast.asn)
       (tag_optional 1 ~label:"data-value" Octet_string.Ast.asn))
end

let ast_of_t t =
  ( Krb_int32.ast_of_t t.data_type
  , Option.map Octet_string.ast_of_t t.data_value )

let t_of_ast (a, b) =
  { data_type = Krb_int32.t_of_ast a
  ; data_value = Option.map Octet_string.t_of_ast b
  }
