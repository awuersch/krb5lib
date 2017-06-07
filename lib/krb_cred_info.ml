open Sexplib.Std
open Asn.S
open Krb_combinators

type t =
  { key : Encryption_key.t
  ; prealm : Realm.t option
  ; pname : Principal_name.t option
  ; flags : Ticket_flags.t option
  ; authtime : Kerberos_time.t option
  ; starttime : Kerberos_time.t option
  ; endtime : Kerberos_time.t option
  ; renew_till : Kerberos_time.t option
  ; srealm : Realm.t option
  ; sname : Principal_name.t option
  ; caddr : Host_addresses.t
  } [@@deriving sexp]

module Ast = struct
  type t =
    Encryption_key.Ast.t
    * (Realm.Ast.t option
    * (Principal_name.Ast.t option
    * (Ticket_flags.Ast.t option
    * (Kerberos_time.Ast.t option
    * (Kerberos_time.Ast.t option
    * (Kerberos_time.Ast.t option
    * (Kerberos_time.Ast.t option
    * (Realm.Ast.t option
    * (Principal_name.Ast.t option
    *  Host_addresses.Ast.t option)))))))))

  let asn =
   sequence
    ( (tag_required ~label:"key" 0 Encryption_key.Ast.asn)
    @ (tag_optional ~label:"prealm" 1 Realm.Ast.asn)
    @ (tag_optional ~label:"pname" 2 Principal_name.Ast.asn)
    @ (tag_optional ~label:"flags" 3 Ticket_flags.Ast.asn)
    @ (tag_optional ~label:"authtime" 5 Kerberos_time.Ast.asn)
    @ (tag_optional ~label:"starttime" 6 Kerberos_time.Ast.asn)
    @ (tag_optional ~label:"endtime" 7 Kerberos_time.Ast.asn)
    @ (tag_optional ~label:"renew-till" 8 Kerberos_time.Ast.asn)
    @ (tag_optional ~label:"srealm" 9 Realm.Ast.asn)
    @ (tag_optional ~label:"sname" 10 Principal_name.Ast.asn)
   -@ (tag_optional ~label:"caddr" 11 Host_addresses.Ast.asn))
end

let ast_of_t t =
  let caddr =
    match t.caddr with
    | [] -> None
    | lst -> Some lst
  in
   (Encryption_key.ast_of_t t.key
  ,(Option.map ~f:Realm.ast_of_t t.prealm
  ,(Option.map ~f:Principal_name.ast_of_t t.pname
  ,(Option.map ~f:Ticket_flags.ast_of_t t.flags
  ,(Option.map ~f:Kerberos_time.ast_of_t t.authtime
  ,(Option.map ~f:Kerberos_time.ast_of_t t.starttime
  ,(Option.map ~f:Kerberos_time.ast_of_t t.endtime
  ,(Option.map ~f:Kerberos_time.ast_of_t t.renew_till
  ,(Option.map ~f:Realm.ast_of_t t.srealm
  ,(Option.map ~f:Principal_name.ast_of_t t.sname
  , Option.map ~f:Host_addresses.ast_of_t caddr))))))))))

let t_of_ast (a, (b, (c, (d, (e, (f, (g, (h, (i, (j, k)))))))))) =
  { key = Encryption_key.t_of_ast a
  ; prealm = Option.map ~f:Realm.t_of_ast b
  ; pname = Option.map ~f:Principal_name.t_of_ast c
  ; flags = Option.map ~f:Ticket_flags.t_of_ast d
  ; authtime = Option.map ~f:Kerberos_time.t_of_ast e
  ; starttime = Option.map ~f:Kerberos_time.t_of_ast f
  ; endtime = Option.map ~f:Kerberos_time.t_of_ast g
  ; renew_till = Option.map ~f:Kerberos_time.t_of_ast h
  ; srealm = Option.map ~f:Realm.t_of_ast i
  ; sname = Option.map ~f:Principal_name.t_of_ast j
  ; caddr = (match k with
      None -> []
    | Some lst -> Host_addresses.t_of_ast lst)
  }
