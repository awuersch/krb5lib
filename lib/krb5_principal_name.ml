open Asn.S
include Krb_combinators

type t =
  { realm          : Realm.t
  ; principal_name : Principal_name.t
  } [@@deriving sexp]

module Ast = struct
  type t = Realm.Ast.t * Principal_name.Ast.t

  let asn =
    sequence2
      (tag_required 0 ~label:"realm" Realm.Ast.asn)
      (tag_required 1 ~label:"principalName" Principal_name.Ast.asn)
end

let ast_of_t t =
  ( Realm.ast_of_t t.realm
  , Principal_name.ast_of_t t.principal_name
  )

let t_of_ast (a, b) =
  { realm = Realm.t_of_ast a
  ; principal_name = Principal_name.t_of_ast b
  }
