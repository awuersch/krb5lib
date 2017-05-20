open Sexplib.Std
open Asn.S
include Krb_combinators

type t =
  { padata   : Pa_data.t list
  ; crealm   : Realm.t
  ; cname    : Principal_name.t
  ; ticket   : Ticket.t
  ; enc_part : Encrypted_data.t
  } [@@deriving sexp]

module Ast = struct
  type t =
      Z.t (* pvno - 5 *)
    * (Z.t (* msg_type *)
    * (Pa_data.Ast.t list option (* Non-empty *)
    * (Realm.Ast.t
    * (Principal_name.Ast.t
    * (Ticket.Ast.t
    *  Encrypted_data.Ast.t)))))

  let asn =
    sequence
      ( tag_required 0 ~label:"pvno" integer
      @ tag_required 1 ~label:"msg-type" integer
      @ tag_optional 2 ~label:"padata" (sequence_of Pa_data.Ast.asn)
      @ tag_required 3 ~label:"crealm" Realm.Ast.asn
      @ tag_required 4 ~label:"cname" Principal_name.Ast.asn
      @ tag_required 5 ~label:"ticket" Ticket.Ast.asn
     -@ tag_required 6 ~label:"enc-part" Encrypted_data.Ast.asn)
end

let app_ast_of_t tag t =
  let padata =
    match t.padata with
    | [] -> None
    | lst -> Some (List.map Pa_data.ast_of_t lst)
  in
    Z.of_int 5 (* Where 5 means krb5 - this is a constant forever *)
  , ( Application_tag.int_of_t tag |> Z.of_int
  , ( padata
  , ( Realm.ast_of_t t.crealm
  , ( Principal_name.ast_of_t t.cname
  , ( Ticket.ast_of_t t.ticket
  , Encrypted_data.ast_of_t t.enc_part)))))

let t_of_ast : Ast.t -> t = function
  | (_, (_, (a, (b, (c, (d, e)))))) -> 
    let padata = match a with
      | None -> []
      | Some l -> List.map Pa_data.t_of_ast l in
    { padata = padata
    ; crealm = Realm.t_of_ast b
    ; cname = Principal_name.t_of_ast c
    ; ticket = Ticket.t_of_ast d
    ; enc_part = Encrypted_data.t_of_ast e
    }
