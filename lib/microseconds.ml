open Sexplib.Std

type t = int32 [@@deriving sexp]

module Ast = struct
  type t = Z.t

  let asn = Asn.S.integer
end

(* convert out of range values to random in range values *)
let ast_of_t t =
  if t < 0l || t > 999999l
  then Random.int32 1000000l |> Z.of_int32
  else Z.of_int32 t

(* convert out of range values to random in range values *)
let t_of_ast ast =
  let i = Z.to_int32 ast in
    if i < 0l || i > 999999l
    then Random.int32 1000000l
    else i
