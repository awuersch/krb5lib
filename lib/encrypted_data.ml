open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { etype : Encryption_type.t
  ; kvno : Uint32.t option
  ; cipher : Octet_string.t (* Decrypts to EncTicketPart *)
  } [@@deriving sexp]

module Ast = struct
  type t = Encryption_type.Ast.t * Uint32.Ast.t option * Cstruct.t

  let asn =
    Application_tag.tag `Ticket
      (sequence3
         (tag_required 0 ~label:"etype" Encryption_type.Ast.asn)
         (tag_optional 1 ~label:"kvno" Uint32.Ast.asn)
         (tag_required 2 ~label:"cipher" Octet_string.Ast.asn))
end

let ast_of_t t =
  ( Encryption_type.ast_of_t t.etype
  , Option.map ~f:Uint32.ast_of_t t.kvno
  , Octet_string.ast_of_t t.cipher )

let t_of_ast (a, b, c) =
  { etype = Encryption_type.t_of_ast a
  ; kvno = Option.map ~f:Uint32.t_of_ast b
  ; cipher = Octet_string.t_of_ast c
  }
