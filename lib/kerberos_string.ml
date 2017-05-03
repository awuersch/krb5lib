open Sexplib.Std

type t = string [@@deriving sexp]

module Ast = struct
  type t = string
  let asn = Asn.S.general_string
end

let ast_of_t t = t

let t_of_ast ast = ast
