open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { name_type : Name_type.t
  ; name_string : Kerberos_string.t list
  } [@@deriving sexp]

module Ast = struct
  type t =  Name_type.Ast.t * Kerberos_string.Ast.t list

  let asn =
    sequence2
      (tag_required 0 ~label:"name_type" Name_type.Ast.asn)
      (tag_required 1 ~label:"name_string"
         (sequence_of Kerberos_string.Ast.asn))

end

let ast_of_t t =
  ( Name_type.ast_of_t t.name_type
  , List.map Kerberos_string.ast_of_t t.name_string)

let t_of_ast (a, b) = {
    name_type = Name_type.t_of_ast a
  ; name_string = List.map Kerberos_string.t_of_ast b
}
