open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { ad_checksum : Checksum.t
  ; i_realm : Realm.t option
  ; i_sname : Principal_name.t option
  ; elements : Authorization_data.t
  } [@@deriving sexp]

module Ast = struct
  type t =
      Checksum.Ast.t
    * Realm.Ast.t option
    * Principal_name.Ast.t option
    * Authorization_data.Ast.t

  let asn =
    sequence4
      (tag_required 0 ~label:"ad-checksum" Checksum.Ast.asn)
      (tag_optional 1 ~label:"i-realm" Realm.Ast.asn)
      (tag_optional 2 ~label:"i-sname" Principal_name.Ast.asn)
      (tag_required 3 ~label:"elements" Authorization_data.Ast.asn)
end

let ast_of_t t =
  ( Checksum.ast_of_t t.ad_checksum
  , Option.map ~f:Realm.ast_of_t t.i_realm
  , Option.map ~f:Principal_name.ast_of_t t.i_sname
  , Authorization_data.ast_of_t t.elements
  )

let t_of_ast (a, b, c, d) =
  { ad_checksum = Checksum.t_of_ast a
  ; i_realm = Option.map ~f:Realm.t_of_ast b
  ; i_sname = Option.map ~f:Principal_name.t_of_ast c
  ; elements = Authorization_data.t_of_ast d
  }
