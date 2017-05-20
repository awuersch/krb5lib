open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { realm : Realm.t
  ; sname : Principal_name.t
  ; enc_part : Encrypted_data.t (* Decrypts to EncTicketPart *)
  } [@@deriving sexp]

module Ast = struct
  type t =
    Z.t * Realm.Ast.t * Principal_name.Ast.t * Encrypted_data.Ast.t

  let asn =
    Application_tag.tag `Ticket
      (sequence4
         (tag_required 0 ~label:"tkt-vno" integer)
         (tag_required 1 ~label:"realm" Realm.Ast.asn)
         (tag_required 2 ~label:"sname" Principal_name.Ast.asn)
         (tag_required 3 ~label:"enc_part" Encrypted_data.Ast.asn))
end

let ast_of_t t =
  ( Z.of_int 5
  , Realm.ast_of_t t.realm
  , Principal_name.ast_of_t t.sname
  , Encrypted_data.ast_of_t t.enc_part )

let t_of_ast (_, a, b, c) =
  { realm = Realm.t_of_ast a
  ; sname = Principal_name.t_of_ast b
  ; enc_part = Encrypted_data.t_of_ast c
  }
