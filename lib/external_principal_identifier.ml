open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { subject_name : Octet_string.t option
  ; issuer_and_serial_number : Octet_string.t option
  ; subject_key_identifier : Octet_string.t option
  } [@@deriving sexp]

module Ast = struct
  type t = Octet_string.Ast.t option * Octet_string.Ast.t option * Octet_string.Ast.t option

  let asn =
    sequence3
      (tag_implicit_optional 0 ~label:"subject_name" Octet_string.Ast.asn)
      (tag_implicit_optional 1 ~label:"issuer_and_serial_number" Octet_string.Ast.asn)
      (tag_implicit_optional 2 ~label:"subject_key_identifier" Octet_string.Ast.asn)
end

let ast_of_t t =
  (Option.map ~f:Octet_string.ast_of_t t.subject_name,
   Option.map ~f:Octet_string.ast_of_t t.issuer_and_serial_number,
   Option.map ~f:Octet_string.ast_of_t t.subject_key_identifier)

let t_of_ast (a, b, c) =
  { subject_name = Option.map ~f:Octet_string.t_of_ast a
  ; issuer_and_serial_number = Option.map ~f:Octet_string.t_of_ast b
  ; subject_key_identifier = Option.map ~f:Octet_string.t_of_ast c
  }
