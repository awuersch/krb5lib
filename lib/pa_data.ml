open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { padata_type : Krb_int32.t
  ; padata_value : Octet_string.t
  } [@@deriving sexp]

module Ast = struct
  type t = Krb_int32.Ast.t * Cstruct.t

  let asn =
    sequence2
      (* First value is 1 not 0 *)
      (tag_required ~label:"padata_type" 1 Krb_int32.Ast.asn)
      (tag_required ~label:"padata_value" 2 Octet_string.Ast.asn)
end

let ast_of_t t =
  (Krb_int32.ast_of_t t.padata_type, Octet_string.ast_of_t t.padata_value)

let t_of_ast (a, b) =
  { padata_type = Krb_int32.t_of_ast a
  ; padata_value = Octet_string.t_of_ast b
  }
