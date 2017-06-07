open Asn.S
include Krb_combinators

type t =
  { safe_body : Krb_safe_body.t
  ; cksum : Checksum.t
  } [@@deriving sexp]

module Ast = struct
  type t =
      Z.t (* pvno - 5 *)
    * Z.t (* msg_type *)
    * Krb_safe_body.Ast.t
    * Checksum.Ast.t

  let asn =
    Application_tag.tag `Krb_safe
      (sequence4
         (tag_required 0 ~label:"pvno" integer)
         (tag_required 1 ~label:"msg-type" integer)
         (tag_required 2 ~label:"safe-body" Krb_safe_body.Ast.asn)
         (tag_required 3 ~label:"cksum" Checksum.Ast.asn))
end

let ast_of_t t =
  ( Z.of_int 5 (* Where 5 means krb5 - this is a constant forever *)
  , Application_tag.int_of_t `Krb_safe |> Z.of_int
  , Krb_safe_body.ast_of_t t.safe_body
  , Checksum.ast_of_t t.cksum
  )

let t_of_ast (_, _, a, b) =
    { safe_body = Krb_safe_body.t_of_ast a
    ; cksum = Checksum.t_of_ast b
    }
