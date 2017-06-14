open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { cusec : Microseconds.t
  ; ctime : Kerberos_time.t
  ; nonce : Uint32.t
  ; pa_checksum : Octet_string.t option
  } [@@deriving sexp]

module Ast = struct type t =
      Microseconds.Ast.t
    * Kerberos_time.Ast.t
    * Uint32.Ast.t
    * Octet_string.Ast.t option

  let asn =
    sequence4
      (tag_required 0 ~label:"cusec" Microseconds.Ast.asn)
      (tag_required 1 ~label:"ctime" Kerberos_time.Ast.asn)
      (tag_required 2 ~label:"nonce" Uint32.Ast.asn)
      (tag_optional 3 ~label:"paChecksum" Octet_string.Ast.asn)
end

let ast_of_t t =
  ( Microseconds.ast_of_t t.cusec
  , Kerberos_time.ast_of_t t.ctime
  , Uint32.ast_of_t t.nonce
  , Option.map ~f:Octet_string.ast_of_t t.pa_checksum
  )

let t_of_ast (a, b, c, d) =
  { cusec = Microseconds.t_of_ast a
  ; ctime = Kerberos_time.t_of_ast b
  ; nonce = Uint32.t_of_ast c
  ; pa_checksum = Option.map ~f:Octet_string.t_of_ast d
  }
