open Sexplib.Std
open Asn.S
open Krb_combinators

module Datum = struct
  type t =
    { data_type : Krb_int32.t
    ; data_value : Octet_string.t option
    } [@@deriving sexp]

  module Ast = struct
    type t = Krb_int32.Ast.t * Octet_string.Ast.t option

    let asn =
      sequence2
        (tag_required ~label:"data-type" 0 Krb_int32.Ast.asn)
        (tag_optional ~label:"data-value" 1 Octet_string.Ast.asn)
  end

  let ast_of_t t =
    Krb_int32.ast_of_t t.data_type,
    Option.map Octet_string.ast_of_t t.data_value

  let t_of_ast (a, b) =
    { data_type = Krb_int32.t_of_ast a
    ; data_value = Option.map Octet_string.t_of_ast b
    }
end

type t = Datum.t list [@@deriving sexp]

module Ast = struct
  type t = Datum.Ast.t list

  let asn = sequence_of Datum.Ast.asn
end

let ast_of_t = List.map Datum.ast_of_t

let t_of_ast = List.map Datum.t_of_ast
