open Asn.S
open Krb_combinators

type t =
  { keytype : Encryption_type.t
  ; keyvalue : Octet_string.t
  } [@@deriving sexp]

module Ast = struct
  type t = Encryption_type.Ast.t * Octet_string.Ast.t

  let asn =
    sequence2
      (tag_required ~label:"keytype" 0 Encryption_type.Ast.asn)
      (tag_required ~label:"keyvalue" 1 Octet_string.Ast.asn)
end

let ast_of_t t =
  ( Encryption_type.ast_of_t t.keytype
  , Octet_string.ast_of_t t.keyvalue )

let t_of_ast (a, b) =
  { keytype = Encryption_type.t_of_ast a
  ; keyvalue = Octet_string.t_of_ast b
  }
