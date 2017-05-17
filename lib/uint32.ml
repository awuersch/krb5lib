open Sexplib.Std

type t = int64 [@@deriving sexp]

module Ast = struct
  type t = Z.t

  let asn = Asn.S.integer
end

(* convert out of range values to random in range values *)
let ast_of_t t =
  if t < 0L || t > 4294967295L
  then Random.int64 4294967295L |> Z.of_int64
  else Z.of_int64 t

(* convert out of range values to random in range values *)
let t_of_ast ast =
  let i = Z.to_int64 ast in
    if i < 0L || i > 4294967295L
    then Random.int64 4294967295L
    else i

module Of_alist (M : Interfaces.ALIST) : Asn1_intf.S with type t = M.t = struct
  include M

  module Ast = Ast

  module Intable = Interfaces.Intable_of_alist(M)

  let ast_of_t t = Z.of_int (Intable.int_of_t t)

  let t_of_ast ast = Intable.t_of_int (Z.to_int ast)

  let sexp_of_t t = sexp_of_string (Intable.string_of_t t)

  let t_of_sexp sexp = Intable.t_of_string (string_of_sexp sexp)
end
