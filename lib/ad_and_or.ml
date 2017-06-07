open Asn.S
open Krb_combinators

type t =
  { condition_count : Krb_int32.t
  ; elements : Authorization_data.t
  } [@@deriving sexp]

module Ast = struct
  type t = Krb_int32.Ast.t * Authorization_data.Ast.t

  let asn =
    (sequence2
       (tag_required 0 ~label:"condition-count" Krb_int32.Ast.asn)
       (tag_required 1 ~label:"elements" Authorization_data.Ast.asn))
end

let ast_of_t t =
  ( Krb_int32.ast_of_t t.condition_count
  , Authorization_data.ast_of_t t.elements )

let t_of_ast (a, b) =
  { condition_count = Krb_int32.t_of_ast a
  ; elements = Authorization_data.t_of_ast b
  }
