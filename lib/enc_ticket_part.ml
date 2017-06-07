open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { flags : Ticket_flags.t
  ; key : Encryption_key.t
  ; crealm : Realm.t
  ; cname : Principal_name.t
  ; transited : Transited_encoding.t
  ; authtime : Kerberos_time.t
  ; starttime : Kerberos_time.t option
  ; endtime : Kerberos_time.t
  ; renew_till : Kerberos_time.t option
  ; caddr : Host_addresses.t
  ; authorization_data : Authorization_data.t
  } [@@deriving sexp]

module Ast = struct
  type t =
    Ticket_flags.Ast.t
    * (Encryption_key.Ast.t
    * (Realm.Ast.t
    * (Principal_name.Ast.t
    * (Transited_encoding.Ast.t
    * (Kerberos_time.Ast.t
    * (Kerberos_time.Ast.t option
    * (Kerberos_time.Ast.t
    * (Kerberos_time.Ast.t option
    (* Non-empty *)
    * (Host_addresses.Ast.t option
    (* Non-empty *)
    * Authorization_data.Ast.t option)))))))))

  let asn =
    Application_tag.tag `Enc_ticket_part
      (sequence
       ( (tag_required ~label:"flags" 0 Ticket_flags.Ast.asn)
       @ (tag_required ~label:"key" 1 Encryption_key.Ast.asn)
       @ (tag_required ~label:"crealm"2  Realm.Ast.asn)
       @ (tag_required ~label:"cname" 3 Principal_name.Ast.asn)
       @ (tag_required ~label:"transited" 4 Transited_encoding.Ast.asn)
       @ (tag_required ~label:"authtime" 5 Kerberos_time.Ast.asn)
       @ (tag_optional ~label:"starttime" 6 Kerberos_time.Ast.asn)
       @ (tag_required ~label:"endtime" 7 Kerberos_time.Ast.asn)
       @ (tag_optional ~label:"renew-till" 8 Kerberos_time.Ast.asn)
       @ (tag_optional ~label:"caddr" 9 Host_addresses.Ast.asn)
      -@ (tag_optional ~label:"authorization_data" 10 Authorization_data.Ast.asn)))
end

let ast_of_t t =
  let caddr =
    match t.caddr with
    | [] -> None
    | lst -> Some lst
  in
  let authorization_data =
    match t.authorization_data with
    | [] -> None
    | lst -> Some lst
  in
   (Ticket_flags.ast_of_t t.flags
  ,(Encryption_key.ast_of_t t.key
  ,(Realm.ast_of_t t.crealm
  ,(Principal_name.ast_of_t t.cname
  ,(Transited_encoding.ast_of_t t.transited
  ,(Kerberos_time.ast_of_t t.authtime
  ,(Option.map ~f:Kerberos_time.ast_of_t t.starttime
  ,(Kerberos_time.ast_of_t t.endtime
  ,(Option.map ~f:Kerberos_time.ast_of_t t.renew_till
  ,(Option.map ~f:Host_addresses.ast_of_t caddr
  , Option.map ~f:Authorization_data.ast_of_t authorization_data))))))))))

let t_of_ast (a, (b, (c, (d, (e, (f, (g, (h, (i, (j, k)))))))))) =
  { flags = Ticket_flags.t_of_ast a
  ; key = Encryption_key.t_of_ast b
  ; crealm = Realm.t_of_ast c
  ; cname = Principal_name.t_of_ast d
  ; transited = Transited_encoding.t_of_ast e
  ; authtime = Kerberos_time.t_of_ast f
  ; starttime = Option.map ~f:Kerberos_time.t_of_ast g
  ; endtime = Kerberos_time.t_of_ast h
  ; renew_till = Option.map ~f:Kerberos_time.t_of_ast i
  ; caddr = (match j with
      None -> []
    | Some lst -> Host_addresses.t_of_ast lst)
  ; authorization_data = match k with
      None -> []
    | Some lst -> Authorization_data.t_of_ast lst
  }
