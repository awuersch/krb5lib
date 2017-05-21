open Sexplib.Std
open Asn.S
include Krb_combinators

type t =
  { ctime      : Kerberos_time.t option
  ; cusec      : Microseconds.t option
  ; stime      : Kerberos_time.t
  ; susec      : Microseconds.t
  ; error_code : Krb_int32.t
  ; crealm     : Realm.t option
  ; cname      : Principal_name.t option
  ; realm      : Realm.t
  ; sname      : Principal_name.t
  ; e_text     : Kerberos_string.t option
  ; e_data     : Octet_string.t option
  } [@@deriving sexp]

module Ast = struct
  type t =
      Z.t (* pvno - 5 *)
    * (Z.t (* msg_type *)
    * (Kerberos_time.Ast.t option
    * (Microseconds.Ast.t option
    * (Kerberos_time.Ast.t
    * (Microseconds.Ast.t
    * (Krb_int32.Ast.t
    * (Realm.Ast.t option
    * (Principal_name.Ast.t option
    * (Realm.Ast.t
    * (Principal_name.Ast.t
    * (Kerberos_string.Ast.t option
    *  Octet_string.Ast.t option)))))))))))

  let asn =
    Application_tag.tag `Krb_error
      (sequence
         ( tag_required 0 ~label:"pvno" integer
         @ tag_required 1 ~label:"msg-type" integer
         @ tag_optional 2 ~label:"ctime" Kerberos_time.Ast.asn
         @ tag_optional 3 ~label:"cusec" Microseconds.Ast.asn
         @ tag_required 4 ~label:"stime" Kerberos_time.Ast.asn
         @ tag_required 5 ~label:"susec" Microseconds.Ast.asn
         @ tag_required 6 ~label:"error-code" Krb_int32.Ast.asn
         @ tag_optional 7 ~label:"crealm" Realm.Ast.asn
         @ tag_optional 8 ~label:"cname" Principal_name.Ast.asn
         @ tag_required 9 ~label:"realm" Realm.Ast.asn
         @ tag_required 10 ~label:"sname" Principal_name.Ast.asn
         @ tag_optional 11 ~label:"e-text" Kerberos_string.Ast.asn
        -@ tag_optional 12 ~label:"e-data" Octet_string.Ast.asn))
end

let ast_of_t t =
    Z.of_int 5 (* Where 5 means krb5 - this is a constant forever *)
  , ( Application_tag.int_of_t `Krb_error |> Z.of_int
  , ( Option.map Kerberos_time.ast_of_t t.ctime
  , ( Option.map Microseconds.ast_of_t t.cusec
  , ( Kerberos_time.ast_of_t t.stime
  , ( Microseconds.ast_of_t t.susec
  , ( Krb_int32.ast_of_t t.error_code
  , ( Option.map Realm.ast_of_t t.crealm
  , ( Option.map Principal_name.ast_of_t t.cname
  , ( Realm.ast_of_t t.realm
  , ( Principal_name.ast_of_t t.sname
  , ( Option.map Kerberos_string.ast_of_t t.e_text
  ,   Option.map Octet_string.ast_of_t t.e_data)))))))))))

let t_of_ast : Ast.t -> t = function
  | (_, (_, (a, (b, (c, (d, (e, (f, (g, (h, (i, (j, k)))))))))))) -> 
    { ctime = Option.map Kerberos_time.t_of_ast a
    ; cusec = Option.map Microseconds.t_of_ast b
    ; stime = Kerberos_time.t_of_ast c
    ; susec = Microseconds.t_of_ast d
    ; error_code = Krb_int32.t_of_ast e
    ; crealm = Option.map Realm.t_of_ast f
    ; cname = Option.map Principal_name.t_of_ast g
    ; realm = Realm.t_of_ast h
    ; sname = Principal_name.t_of_ast i
    ; e_text = Option.map Kerberos_string.t_of_ast j
    ; e_data = Option.map Octet_string.t_of_ast k
    }
