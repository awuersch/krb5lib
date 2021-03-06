open Sexplib.Std

type t = int64 [@@deriving sexp]

module Ast = struct
  type t = Z.t

  let asn = Asn.S.integer
end

(* convert out of range values to random in range values *)
let ast_of_t t =
  if t < 0L || t > 4294967295L
  then Random.int64 4294967296L |> Z.of_int64
  else Z.of_int64 t

(* convert out of range values to random in range values *)
let t_of_ast ast =
  let i = Z.to_int64 ast in
    if i < 0L || i > 4294967295L
    then Random.int64 4294967296L
    else i
