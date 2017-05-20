open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { crealm : Realm.t
  ; cname : Principal_name.t
  ; cksum : Checksum.t option
  ; cusec : Microseconds.t
  ; ctime : Kerberos_time.t
  ; subkey : Encryption_key.t option
  ; seq_number : Uint32.t option
  ; authorization_data : Authorization_data.t
  } [@@deriving sexp]

module Ast = struct
  type t =
    Z.t
    * (Realm.Ast.t
    * (Principal_name.Ast.t
    * (Checksum.Ast.t option
    * (Microseconds.Ast.t
    * (Kerberos_time.Ast.t
    * (Encryption_key.Ast.t option
    * (Uint32.Ast.t option
    *  Authorization_data.Ast.t option)))))))

  let asn =
    Application_tag.tag `Authenticator
      (sequence
       ( (tag_required ~label:"authenticator-vno" 0 integer)
       @ (tag_required ~label:"crealm" 1 Realm.Ast.asn)
       @ (tag_required ~label:"cname" 2 Principal_name.Ast.asn)
       @ (tag_optional ~label:"cksum" 3 Checksum.Ast.asn)
       @ (tag_required ~label:"cusec" 4 Microseconds.Ast.asn)
       @ (tag_required ~label:"ctime" 5 Kerberos_time.Ast.asn)
       @ (tag_optional ~label:"subkey" 6 Encryption_key.Ast.asn)
       @ (tag_optional ~label:"seq-number" 7 Uint32.Ast.asn)
      -@ (tag_optional ~label:"authorization-data" 8 Authorization_data.Ast.asn)))
end

let ast_of_t t =
  let authorization_data =
    match t.authorization_data with
    | [] -> None
    | lst -> Some lst
  in
   (Z.of_int 5 (* pvno *)
  ,(Realm.ast_of_t t.crealm
  ,(Principal_name.ast_of_t t.cname
  ,(Option.map Checksum.ast_of_t t.cksum
  ,(Microseconds.ast_of_t t.cusec
  ,(Kerberos_time.ast_of_t t.ctime
  ,(Option.map Encryption_key.ast_of_t t.subkey
  ,(Option.map Uint32.ast_of_t t.seq_number
  , Option.map Authorization_data.ast_of_t authorization_data))))))))

let t_of_ast (_, (a, (b, (c, (d, (e, (f, (g, h)))))))) =
  { crealm = Realm.t_of_ast a
  ; cname = Principal_name.t_of_ast b
  ; cksum = Option.map Checksum.t_of_ast c
  ; cusec = Microseconds.t_of_ast d
  ; ctime = Kerberos_time.t_of_ast e
  ; subkey = Option.map Encryption_key.t_of_ast f
  ; seq_number = Option.map Uint32.t_of_ast g
  ; authorization_data = (match h with
      None -> []
    | Some lst -> Authorization_data.t_of_ast lst)
  }
