open Sexplib.Std
open Asn.S
include Krb_combinators

type t =
  { dh_signed_data : Octet_string.t
  ; server_dh_nonce : Octet_string.t option
  } [@@deriving sexp]

module Ast = struct
  type t = Octet_string.Ast.t * Octet_string.Ast.t option

  let asn =
    sequence2
      (tag_implicit_required 0 ~label:"dhSignedData" Octet_string.Ast.asn)
      (tag_optional 1 ~label:"serverDHNonce" Octet_string.Ast.asn)
end

let ast_of_t t =
  ( Octet_string.ast_of_t t.dh_signed_data
  , Option.map ~f:Octet_string.ast_of_t t.server_dh_nonce
  )

let t_of_ast (a, b) =
  { dh_signed_data = Octet_string.t_of_ast a
  ; server_dh_nonce = Option.map ~f:Octet_string.t_of_ast b
  }
