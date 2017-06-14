open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { signed_auth_pack : Octet_string.t
  ; trusted_certifiers : External_principal_identifier.t list
  ; kdc_pk_id : Octet_string.t option
  } [@@deriving sexp]

module Ast = struct
  type t =
      Octet_string.Ast.t
    * External_principal_identifier.Ast.t list option
    * Octet_string.Ast.t option

  let asn =
    sequence3
      (tag_implicit_required 0 ~label:"signed_auth_pack" Octet_string.Ast.asn)
      (tag_implicit_optional 1 ~label:"trusted_certifiers" (sequence_of External_principal_identifier.Ast.asn))
      (tag_implicit_optional 2 ~label:"kdc_pk_id" Octet_string.Ast.asn)
end

let ast_of_t t =
  let certifiers =
    match t.trusted_certifiers with
    | [] -> None
    | lst -> Some (List.map External_principal_identifier.ast_of_t lst)
  in
  (Octet_string.ast_of_t t.signed_auth_pack,
   certifiers,
   Option.map ~f:Octet_string.ast_of_t t.kdc_pk_id)


let t_of_ast (a, b, c) =
  { signed_auth_pack = Octet_string.t_of_ast a
  ; trusted_certifiers = (match b with
      None -> []
    | Some lst -> List.map External_principal_identifier.t_of_ast lst)
  ; kdc_pk_id = Option.map ~f:Octet_string.t_of_ast c
  }
