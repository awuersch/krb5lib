(*---------------------------------------------------------------------------
   Copyright (c) 2017 Tony Wuersch. All rights reserved.
   Copyright (c) 2015 Brandon Bohrer. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
   %%NAME%% %%VERSION%%
  ---------------------------------------------------------------------------*)

(** Kerberos5 messages and ASN.1 syntaxes as O'Caml records and types.

    {e %%VERSION%% — {{:%%PKG_HOMEPAGE%% }homepage}} *)

(** {1 Krb5lib} *)
module Msg : sig

  module Asn1_intf : sig
    module type S = sig
      type t
  
      module Ast : sig
        type t
        val asn : t Asn.t
      end
  
      val ast_of_t : t -> Ast.t
      val t_of_ast : Ast.t -> t
      val sexp_of_t : t -> Sexplib.Sexp.t
      val t_of_sexp : Sexplib.Sexp.t -> t
    end
  end

  module Interfaces : sig
    module type Intable = sig
      type t
      val t_of_int : int -> t
      val int_of_t : t -> int
    end

    module OrderedType_of_Intable (M : Intable) : sig
      type t = M.t
      val compare : t -> t -> int
    end

    module type ALIST = sig
      type t
      val alist : (t * int) list
    end

    (* Slower than a custom Intable implementation *)
    module Intable_of_alist (M : ALIST) : sig
      type t = M.t
      val t_of_int : int -> t
      val int_of_t : t -> int
    end
  end

  module Krb_int32 : sig
    include Asn1_intf.S with type t = int32 and type Ast.t = Z.t

    module Of_alist (M : Interfaces.ALIST) : Asn1_intf.S with type t = M.t
  end

  (* testing -- Uint32 = Krb_int32 does not seem to work ... *)
  module Uint32 : sig
    include Asn1_intf.S with type t = int32 and type Ast.t = Z.t

    module Of_alist (M : Interfaces.ALIST) : Asn1_intf.S with type t = M.t
  end

  module Octet_string :
    Asn1_intf.S with type t = string and type Ast.t = Cstruct.t

  module Kerberos_string :
    Asn1_intf.S with type t = string and type Ast.t = string

  (* testing --- Realm = Kerberos_string does not seem to work ... *)
  module Realm :
    Asn1_intf.S with type t = string and type Ast.t = string

  module Kerberos_time : sig
    type t =
    { year : int
    ; month : int
    ; day : int
    ; hour : int
    ; minute : int
    ; second : int
    }
    include Asn1_intf.S with type t := t and type Ast.t = Ptime.t
  end

  module Application_tag : sig
    type t =
    [ `Ticket
    | `Authenticator
    | `Enc_ticket_part
    | `As_req
    | `As_rep
    | `Tgs_req
    | `Tgs_rep
    | `Ap_req
    | `Ap_rep
    | `Reserved16
    | `Reserved17
    | `Krb_safe
    | `Krb_priv
    | `Krb_cred
    | `Enc_as_rep_part
    | `Enc_tgs_rep_part
    | `Enc_ap_rep_part
    | `Enc_krb_priv_part
    | `Enc_krb_cred_part
    | `Krb_error
    ]

    val int_of_t : t -> int
    val t_of_int_exn : int -> t
    val tag : t -> t Asn.t -> t Asn.t
    val string_of_t : t -> string
    val sexp_of_t : t -> Sexplib.Sexp.t
    val t_of_sexp : Sexplib.Sexp.t -> t
  end

  module Name_type : sig
    module M : sig
      type t =
      | Unknown
      | Principal
      | Srv_inst
      | Srv_hst
      | Srv_xhst
      | Uid
      | X500_principal
      | Smtp_name
      | Enterprise

      val alist : (t * int) list
    end

    include Asn1_intf.S with
          type t = M.t
      and type Ast.t = Krb_int32.Of_alist(M).Ast.t
  end

  module Encryption_type : sig
    type ty =
    | Des_cbc_crc
    | Des_cbc_md4
    | Des_cbc_md5
    | Reserved4
    | Des3_cbc_md5
    | Reserved6
    | Des3_cbc_sha1
    | Dsa_with_sha1_cms_oid
    | Md5WithRSAEncryption_cmsOID
    | Sha1WithRSAEncryption_cmsOID
    | Rc2CBC_EnvOID
    | Rsa_encryption_envOID
    | Rsa_es_oaepSenvOID
    | Des_ede3_cbc_envOID
    | Des3_cbc_sha1_kd
    | Aes128_cts_hmac_sha1_96
    | Aes256_cts_hmac_sha1_96
    | Rc4_hmac
    | Rc4_hmac_exp
    | Subkey_keymaterial

    (* I bet this list will grow longer one day. *)
    val is_weak : ty -> bool

    (* CR bbohrer: This may not be 100% correct. I just followed the following rule from RFC 4120:
     RC4, DES, 3DES and anything in RFC 1510 are not "newer"
    *)
    (* Certain steps of the krb5 protocol are different depending on how old the encryption type is.
       Thus we expose a function to test whether an encryption type is considered new or old. *)
    val is_newer_than_rfc_4120 : ty -> bool

    module M : sig
      type t = ty
      val alist : (t * int) list
    end

    include Asn1_intf.S with
          type t = M.t
      and type Ast.t = Krb_int32.Of_alist(M).Ast.t
  end

  module Address_type : sig
    module M : sig
      type t =
      | Ipv4
      | Directional
      | Chaos_net
      | Xns
      | Iso
      | Decnet_phase_iv
      | Apple_talk_ddp
      | Net_bios
      | Ipv6

      val alist : (t * int) list
    end

    include Asn1_intf.S with
          type t = M.t
      and type Ast.t = Krb_int32.Of_alist(M).Ast.t
  end

  module Ticket_flags : sig
    module Flags : sig
      type t =
      | Reserved
      | Forwardable
      | Forwarded
      | Proxiable
      | Proxy
      | May_postdate
      | Postdated
      | Invalid
      | Renewable
      | Initial
      | Pre_authent
      | Hw_authent
      | Transited_policy_checked
      | Ok_as_delegate

      val alist : (t * int) list
      module Encoding_options : sig
        val min_bits : int
      end
    end

    module FlagSet : Set.S

    include Asn1_intf.S with
         type t = FlagSet.t
     and type Ast.t = bool array
  end

  module Kdc_options : sig
    module Flags : sig
      type t =
      | Reserved
      | Forwardable
      | Forwarded
      | Proxiable
      | Proxy
      | Allow_postdate
      | Postdated
      | Unused7
      | Renewable
      | Unused9
      | Unused10
      | Opt_hardware_auth
      | Unused12
      | Unused13
      | Unused15
      | Disable_transited_check
      | Renewable_ok
      | Ext_ticket_in_skey
      | Renew
      | Validate

      val alist : (t * int) list
      module Encoding_options : sig
        val min_bits : int
      end
    end

    module FlagSet : Set.S

    include Asn1_intf.S with
         type t = FlagSet.t
     and type Ast.t = bool array
  end

  module Principal_name : sig
    type t =
      { name_type : Name_type.t
      ; name_string : Kerberos_string.t list
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Name_type.Ast.t * Kerberos_string.Ast.t list
  end

  module Encrypted_data : sig
    type t =
      { etype : Encryption_type.t
      ; kvno : Uint32.t option
      ; cipher : Octet_string.t (* Decrypts to EncTicketPart *)
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Encryption_type.Ast.t * Uint32.Ast.t option * Cstruct.t
  end

  module Encryption_key : sig
    type t =
      { keytype : Encryption_type.t
      ; keyvalue : Octet_string.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Encryption_type.Ast.t * Octet_string.Ast.t
  end

  module Transited_encoding : sig
    type t =
      { tr_type : Krb_int32.t
      ; contents : Octet_string.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Krb_int32.Ast.t * Octet_string.Ast.t
  end

  module Host_address : sig
    type t =
      { addr_type : Address_type.t
      ; address : Octet_string.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Address_type.Ast.t * Cstruct.t
  end

  module Host_addresses : sig
    type t = Host_address.t list
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Host_address.Ast.t list
  end

  module Pa_data : sig
    type t =
      { padata_type : Krb_int32.t
      ; padata_value : Octet_string.t
      } [@@deriving sexp]
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Krb_int32.Ast.t * Cstruct.t
  end

  module Authorization_data : sig
    module Datum : sig
      type t =
        { ad_type : Krb_int32.t
        ; ad_data : Octet_string.t
        }
      include Asn1_intf.S with
            type t := t
        and type Ast.t = Krb_int32.Ast.t * Octet_string.Ast.t
    end

    type t = Datum.t list
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Datum.Ast.t list
  end

  module Enc_ticket_part : sig
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
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t =
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
  end

  module Ticket : sig
    type t =
      { realm : Realm.t
      ; sname : Principal_name.t
      ; enc_part : Encrypted_data.t (* Decrypts to EncTicketPart *)
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t =
            int * Realm.Ast.t * Principal_name.Ast.t * Encrypted_data.Ast.t
  end

  module Kdc_req_body : sig
    (* CR bbohrer: Encode invariant that cname is only used for as-req *)
    type t =
      { kdc_options : Kdc_options.t
      ; cname : Principal_name.t option (* Used only in As-req *)
      ; realm : Realm.t
      ; sname : Principal_name.t option
      ; from : Kerberos_time.t option
      ; till : Kerberos_time.t
      ; rtime : Kerberos_time.t option
      ; nonce : Uint32.t
      ; etype : Encryption_type.t list (* In preference order*)
      ; addresses : Host_addresses.t option
      ; enc_authorization_data : Encrypted_data.t option
      ; additional_tickets :  Ticket.t list
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t =
              Kdc_options.Ast.t
            * (Principal_name.Ast.t option (* Used only in As-req *)
            * (Realm.Ast.t
            * (Principal_name.Ast.t option
            * (Kerberos_time.Ast.t option
            * (Kerberos_time.Ast.t
            * (Kerberos_time.Ast.t option
            * (Uint32.Ast.t
            * (Encryption_type.Ast.t list (* In preference order*)
            * (Host_addresses.Ast.t option
            * (Encrypted_data.Ast.t option
            *  Ticket.Ast.t list option))))))))))
  end

  module Kdc_req : sig
    type t =
      { msg_type : [ `As_req | `Tgs_req ]
      ; padata : Pa_data.t list
      ; req_body : Kdc_req_body.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t =
              int (* pvno - 5 *)
            * int (* msg_type *)
            * Pa_data.Ast.t list option (* Non-empty *)
            * Kdc_req_body.Ast.t
  end

  module As_req : sig
    type t =
      { padata : Pa_data.t list
      ; req_body : Kdc_req_body.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Kdc_req.Ast.t
  end

  module Types : sig
    val all  : (string * (module Asn1_intf.S)) list
    val some : (string * (module Asn1_intf.S)) list
    val bad  : (string * (module Asn1_intf.S)) list
  end
end

(*---------------------------------------------------------------------------
   Copyright (c) 2017 Tony Wuersch
   Copyright (c) 2015 Brandon Bohrer

   Permission to use, copy, modify, and/or distribute this software for any
   purpose with or without fee is hereby granted, provided that the above
   copyright notice and this permission notice appear in all copies.

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
  ---------------------------------------------------------------------------*)
