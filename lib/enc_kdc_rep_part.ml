open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { key : Encryption_key.t
  ; last_req : Last_req.t
  ; nonce : Uint32.t
  ; key_expiration : Kerberos_time.t option
  ; flags : Ticket_flags.t
  ; authtime : Kerberos_time.t
  ; starttime : Kerberos_time.t option
  ; endtime : Kerberos_time.t
  ; renew_till : Kerberos_time.t option
  ; srealm : Realm.t
  ; sname : Principal_name.t
  ; caddr : Host_addresses.t
  } [@@deriving sexp]

module Ast = struct
  type t =
    Encryption_key.Ast.t
    * (Last_req.Ast.t
    * (Uint32.Ast.t
    * (Kerberos_time.Ast.t option
    * (Ticket_flags.Ast.t
    * (Kerberos_time.Ast.t
    * (Kerberos_time.Ast.t option
    * (Kerberos_time.Ast.t
    * (Kerberos_time.Ast.t option
    * (Realm.Ast.t
    * (Principal_name.Ast.t
    * Host_addresses.Ast.t option))))))))))

  let app_asn tag =
    Application_tag.tag tag
      (sequence
       ( (tag_required ~label:"key" 0 Encryption_key.Ast.asn)
       @ (tag_required ~label:"last_req" 1 Last_req.Ast.asn)
       @ (tag_required ~label:"nonce" 2 Uint32.Ast.asn)
       @ (tag_optional ~label:"key_expiration" 3 Kerberos_time.Ast.asn)
       @ (tag_required ~label:"flags" 4 Ticket_flags.Ast.asn)
       @ (tag_required ~label:"authtime" 5 Kerberos_time.Ast.asn)
       @ (tag_optional ~label:"starttime" 6 Kerberos_time.Ast.asn)
       @ (tag_required ~label:"endtime" 7 Kerberos_time.Ast.asn)
       @ (tag_optional ~label:"renew-till" 8 Kerberos_time.Ast.asn)
       @ (tag_required ~label:"srealm" 9 Realm.Ast.asn)
       @ (tag_required ~label:"sname" 10 Principal_name.Ast.asn)
      -@ (tag_optional ~label:"caddr" 11 Host_addresses.Ast.asn)))
end

let ast_of_t t =
  let caddr =
    match t.caddr with
    | [] -> None
    | lst -> Some lst
  in
   (Encryption_key.ast_of_t t.key
  ,(Last_req.ast_of_t t.last_req
  ,(Uint32.ast_of_t t.nonce
  ,(Option.map Kerberos_time.ast_of_t t.key_expiration
  ,(Ticket_flags.ast_of_t t.flags
  ,(Kerberos_time.ast_of_t t.authtime
  ,(Option.map Kerberos_time.ast_of_t t.starttime
  ,(Kerberos_time.ast_of_t t.endtime
  ,(Option.map Kerberos_time.ast_of_t t.renew_till
  ,(Realm.ast_of_t t.srealm
  ,(Principal_name.ast_of_t t.sname
  , Option.map Host_addresses.ast_of_t caddr)))))))))))

let t_of_ast (a, (b, (c, (d, (e, (f, (g, (h, (i, (j, (k, l))))))))))) =
  { key = Encryption_key.t_of_ast a
  ; last_req = Last_req.t_of_ast b
  ; nonce = Uint32.t_of_ast c
  ; key_expiration = Option.map Kerberos_time.t_of_ast d
  ; flags = Ticket_flags.t_of_ast e
  ; authtime = Kerberos_time.t_of_ast f
  ; starttime = Option.map Kerberos_time.t_of_ast g
  ; endtime = Kerberos_time.t_of_ast h
  ; renew_till = Option.map Kerberos_time.t_of_ast i
  ; srealm = Realm.t_of_ast j
  ; sname = Principal_name.t_of_ast k
  ; caddr = (match l with
      None -> []
    | Some lst -> Host_addresses.t_of_ast lst)
  }
