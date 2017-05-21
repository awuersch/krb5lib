open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { method_data : Pa_data.t list
  } [@@deriving sexp]

module Ast = struct
  type t = Pa_data.Ast.t list

  let asn = sequence_of Pa_data.Ast.asn
end

let ast_of_t t = List.map Pa_data.ast_of_t t.method_data

let t_of_ast a = { method_data = List.map Pa_data.t_of_ast a; }
