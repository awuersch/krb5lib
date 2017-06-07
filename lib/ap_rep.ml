open Asn.S
include Krb_combinators

type t =
  { enc_part : Encrypted_data.t
  } [@@deriving sexp]

module Ast = struct
  type t =
      Z.t (* pvno - 5 *)
    * Z.t (* msg_type *)
    * Encrypted_data.Ast.t

  let asn =
    Application_tag.tag `Ap_req
      (sequence3
         (tag_required 0 ~label:"pvno" integer)
         (tag_required 1 ~label:"msg-type" integer)
         (tag_required 2 ~label:"enc-part" Encrypted_data.Ast.asn))
end

let ast_of_t t =
  ( Z.of_int 5 (* Where 5 means krb5 - this is a constant forever *)
  , Application_tag.int_of_t `Ap_req |> Z.of_int
  , Encrypted_data.ast_of_t t.enc_part
  )

let t_of_ast : Ast.t -> t = function
  | (_, _, a) -> 
    { enc_part = Encrypted_data.t_of_ast a
    }
