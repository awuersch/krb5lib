open Sexplib.Std
open Asn.S
open Krb_combinators

module Datum = struct
  type t =
    { ad_type : Krb_int32.t
    ; ad_data : Octet_string.t
    } [@@deriving sexp]

  module Ast = struct
    type t = Krb_int32.Ast.t * Octet_string.Ast.t

    let asn =
      sequence2
        (tag_required ~label:"ad_type" 0 Krb_int32.Ast.asn)
        (tag_required ~label:"ad_data" 1 Octet_string.Ast.asn)
  end

  let ast_of_t t =
    Krb_int32.ast_of_t t.ad_type, Octet_string.ast_of_t t.ad_data

  let t_of_ast (a, b) =
    { ad_type = Krb_int32.t_of_ast a
    ; ad_data = Octet_string.t_of_ast b
    }
end

type t = Datum.t list

module Ast = struct
  type t = Datum.Ast.t list [@@deriving sexp]

  let asn = sequence_of Datum.Ast.asn
end

let ast_of_t = List.map Datum.ast_of_t

let t_of_ast = List.map Datum.t_of_ast
