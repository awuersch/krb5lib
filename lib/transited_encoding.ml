open Asn.S
open Krb_combinators

type t =
  { tr_type : Krb_int32.t
  ; contents : Octet_string.t
  } [@@deriving sexp]

module Ast = struct
  type t = Krb_int32.Ast.t * Octet_string.Ast.t

  let asn =
    sequence2
      (tag_required ~label:"tr_type" 0 Krb_int32.Ast.asn)
      (tag_required ~label:"contents" 1 Octet_string.Ast.asn)
end

let ast_of_t t =
  ( Krb_int32.ast_of_t t.tr_type
  , Octet_string.ast_of_t t.contents)

let t_of_ast (a, b) = {
  tr_type = Krb_int32.t_of_ast a;
  contents = Octet_string.t_of_ast b
}
