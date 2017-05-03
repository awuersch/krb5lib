open Sexplib.Std

module type S = sig
  type t [@@deriving sexp]
  module Ast : sig
    type t

    val asn : t Asn.t
  end

  val ast_of_t : t -> Ast.t

  val t_of_ast : Ast.t -> t

  (* val sexp_of_t : t -> Sexplib.Sexp.t *)

  (* val t_of_sexp : Sexplib.Sexp.t -> t *)
end
