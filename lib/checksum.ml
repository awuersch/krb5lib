open Asn.S
open Krb_combinators

type t =
  { cksumtype : Checksum_type.t
  ; checksum : Octet_string.t
  } [@@deriving sexp]

module Ast = struct
  type t = Checksum_type.Ast.t * Octet_string.Ast.t

  let asn =
    sequence2
      (tag_required ~label:"cksumtype" 0 Checksum_type.Ast.asn)
      (tag_required ~label:"checksum" 1 Octet_string.Ast.asn)
end

let ast_of_t t =
  ( Checksum_type.ast_of_t t.cksumtype
  , Octet_string.ast_of_t t.checksum )

let t_of_ast (a, b) =
  { cksumtype = Checksum_type.t_of_ast a
  ; checksum = Octet_string.t_of_ast b
  }
