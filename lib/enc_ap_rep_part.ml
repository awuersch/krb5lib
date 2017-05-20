open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { ctime : Kerberos_time.t
  ; cusec : Microseconds.t
  ; subkey : Encryption_key.t option
  ; seq_number : Uint32.t option
  } [@@deriving sexp]

module Ast = struct
  type t =
      Kerberos_time.Ast.t
    * Microseconds.Ast.t
    * Encryption_key.Ast.t option
    * Uint32.Ast.t option

  let asn =
    Application_tag.tag `Enc_ap_rep_part
      (sequence4
        (tag_required ~label:"ctime" 0 Kerberos_time.Ast.asn)
        (tag_required ~label:"cusec" 1 Microseconds.Ast.asn)
        (tag_optional ~label:"subkey" 2 Encryption_key.Ast.asn)
        (tag_optional ~label:"seq_number" 3 Uint32.Ast.asn))
end

let ast_of_t t =
  ( Kerberos_time.ast_of_t t.ctime
  , Microseconds.ast_of_t t.cusec
  , Option.map Encryption_key.ast_of_t t.subkey
  , Option.map Uint32.ast_of_t t.seq_number )

let t_of_ast (a, b, c, d) =
  { ctime = Kerberos_time.t_of_ast a
  ; cusec = Microseconds.t_of_ast b
  ; subkey = Option.map Encryption_key.t_of_ast c
  ; seq_number = Option.map Uint32.t_of_ast d
  }
