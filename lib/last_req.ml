open Sexplib.Std
open Asn.S
open Krb_combinators

module Datum = struct
  type t =
    { lr_type : Krb_int32.t
    ; lr_value : Kerberos_time.t
    } [@@deriving sexp]

  module Ast = struct
    type t = Krb_int32.Ast.t * Kerberos_time.Ast.t

    let asn =
      sequence2
        (tag_required ~label:"lr-type" 0 Krb_int32.Ast.asn)
        (tag_required ~label:"lr-value" 1 Kerberos_time.Ast.asn)
  end

  let ast_of_t t =
    Krb_int32.ast_of_t t.lr_type,
    Kerberos_time.ast_of_t t.lr_value

  let t_of_ast (a, b) =
    { lr_type = Krb_int32.t_of_ast a
    ; lr_value = Kerberos_time.t_of_ast b
    }
end

type t = Datum.t list [@@deriving sexp]

module Ast = struct
  type t = Datum.Ast.t list

  let asn = sequence_of Datum.Ast.asn
end

let ast_of_t = List.map Datum.ast_of_t

let t_of_ast = List.map Datum.t_of_ast
