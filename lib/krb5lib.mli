(*---------------------------------------------------------------------------
   Copyright (c) 2017 Tony Wuersch. All rights reserved.
   Copyright (c) 2015 Brandon Bohrer. All rights reserved.
   See LICENSE.md *)

(** Kerberos5 messages and ASN.1 syntaxes as O'Caml records and types.

    Embeds
    {b References}
    {ul
    {  {{:https;//tools.ietf.org/html/rfc4120#appendixA}The
         Kerberos Authentication Service (V5)}, Appendex A. ASN.1 module}
    {  {{:https;//tools.ietf.org/html/rfc4120}The
         Kerberos Authentication Service (V5)}}
    {}
    
    {e %%VERSION%% — {{:%%PKG_HOMEPAGE%% }homepage}} *)

(** {1 Krb5lib} Krb5 message types *)
module Msg : sig

  module Asn1_intf : sig
    (** Each ASN.1 type matches or extends this *)
    module type S = sig
      type t
  
      (** Abstract syntax tree, typed per asn1-combinators package *)
      module Ast : sig
        type t
        val asn : t Asn.t
      end
  
      (* marshalling *)
      val ast_of_t : t -> Ast.t

      (* de-marshalling *)
      val t_of_ast : Ast.t -> t

      (* serializing *)
      val sexp_of_t : t -> Sexplib.Sexp.t

      (* de-serializing *)
      val t_of_sexp : Sexplib.Sexp.t -> t
    end
  end

  module Interfaces : sig
    (** variant type -> int map *)
    module type ALIST = sig
      type t
      val alist : (t * int) list
    end

    (** encoding and decoding *)
    module type Intable = sig
      type t
      val t_of_int : int -> t
      val int_of_t : t -> int
    end

    (** variant types compare via ints *)
    module OrderedType_of_Intable (M : Intable) : sig
      type t = M.t
      val compare : t -> t -> int
    end

    (** Slower than a custom Intable implementation *)
    module Intable_of_alist (M : ALIST) : sig
      type t = M.t
      val t_of_int : int -> t
      val int_of_t : t -> int
    end
  end

  (** KerberosString type, see {{:https://tools.ietf.org/html/rfc4120#section-5.2.1}rfc4120 Section 5.2.1. KerberosString} *)
  module Kerberos_string :
    Asn1_intf.S with type t = string and type Ast.t = string

  (** Int32 type, see {{:https://tools.ietf.org/html/rfc4120#section-5.2.4}rfc4120 Section 5.2.4. Constrained Integer Types} *)
  module Krb_int32 : sig
    (** to monomorphic type *)
    include Asn1_intf.S with type t = int32 and type Ast.t = Z.t

    (** maps variant types to ASN.1 types, given a mapping to int *)
    module Of_alist (M : Interfaces.ALIST) : Asn1_intf.S with type t = M.t
  end

  (** UInt32 type, see {{:https://tools.ietf.org/html/rfc4120#section-5.2.4}rfc4120 Section 5.2.4. Constrained Integer Types} *)
  module Uint32 : sig
    (** to monomorphic type *)
    include Asn1_intf.S with type t = int64 and type Ast.t = Z.t

    (** maps variant types to ASN.1 types, given a mapping to int *)
    module Of_alist (M : Interfaces.ALIST) : Asn1_intf.S with type t = M.t
  end

  (** Realm type, see {{:https://tools.ietf.org/html/rfc4120#section-5.2.2}rfc4120 Section 5.2.2. Realm and PrincipalName} *)
  module Realm :
    Asn1_intf.S with type t = string and type Ast.t = string

  (** ASN.1 Octet_string type *)
  module Octet_string :
    Asn1_intf.S with type t = string and type Ast.t = Cstruct.t

  (** Realm type, see {{:https://tools.ietf.org/html/rfc4120#section-5.2.3}rfc4120 Section 5.2.3. KerberosTime} *)
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

  (** Application tag numbers, see {{:https://tools.ietf.org/html/rfc4120#section-5.10}rfc4120 Section 5.10. Application Tag Numbers} *)
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

  (** Principal Name type, see {{:https://tools.ietf.org/html/rfc4120#section-6.2}rfc4120 Section 6.2. Principal Names} *)
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

  (** Encryption type, see {{https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-1} Kerberos Encryption Type Numbers, Last updated 2017-03-02} *)
  module Encryption_type : sig
    type ty =
    | Reserved_0
    | Des_cbc_crc
    | Des_cbc_md4
    | Des_cbc_md5
    | Reserved_1
    | Des3_cbc_md5
    | Reserved_2
    | Des3_cbc_sha1
    | DsaWithSHA1_CmsOID
    | Md5WithRSAEncryption_CmsOID
    | Sha1WithRSAEncryption_CmsOID
    | Rc2CBC_EnvOID
    | RsaEncryption_EnvOID
    | RsaES_OAEP_ENV_OID
    | Des_ede3_cbc_Env_OID
    | Des3_cbc_sha1_kd
    | Aes128_cts_hmac_sha1_96
    | Aes256_cts_hmac_sha1_96
    | Aes128_cts_hmac_sha256_128
    | Aes256_cts_hmac_sha384_192
    | Rc4_hmac
    | Rc4_hmac_exp
    | Camellia128_cts_cmac
    | Camellia256_cts_cmac
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

  (** Checksum type, see {{https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-1} Kerberos Encryption Type Numbers, Last updated 2017-03-02} *)
  module Checksum_type : sig
    module M : sig
      type t =
      | Reserved_0
      | CRC32
      | Rsa_md4
      | Rsa_md4_des
      | Des_mac
      | Des_mac_k
      | Rsa_md4_des_k
      | Rsa_md5
      | Rsa_md5_des
      | Rsa_md5_des3
      | Sha1_unkeyed_0
      | Hmac_sha1_des3_kd
      | Hmac_sha1_des3
      | Sha1_unkeyed_1
      | Hmac_sha1_96_aes128
      | Hmac_sha1_96_aes256
      | Cmac_camellia128
      | Cmac_camellia256
      | Hmac_sha256_128_aes128
      | Hmac_sha256_192_aes256
      | Reserved_1

      val alist : (t * int) list
    end

    include Asn1_intf.S with
          type t = M.t
      and type Ast.t = Krb_int32.Of_alist(M).Ast.t
  end

  (** Address type, see {{:https://tools.ietf.org/html/rfc4120#section-7.5.3}rfc4120 Section 7.5.3 Principal Names} *)
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

  (** Tcp extension, see {{https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-3} Kerberos Encryption Type Numbers, Last updated 2017-03-02} *)
  module Tcp_extension : sig
    module M : sig
      type t =
      | Krb5_over_TLS
      | Reserved_0

      val alist : (t * int) list
    end

    include Asn1_intf.S with
          type t = M.t
      and type Ast.t = Krb_int32.Of_alist(M).Ast.t
  end

  (** FAST Armor type, see {{https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-5} FAST Armor Types, Last updated 2017-03-02} *)
  module Fast_armor_type : sig
    module M : sig
      type t =
      | Reserved_0
      | FX_FAST_ARMOR_AP_REQUEST

      val alist : (t * int) list
    end

    include Asn1_intf.S with
          type t = M.t
      and type Ast.t = Krb_int32.Of_alist(M).Ast.t
  end

  (** Transport type, see {{https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-9} Kerberos Message Transport Types, Last updated 2017-03-02} *)
  module Transport_type : sig
    module M : sig
      type t =
      | Reserved_0
      | UDP
      | TCP
      | TLS

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

  (** FAST options, see {{https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-6} FAST Options, Last updated 2017-03-02} *)
  module Fast_options : sig
    module Flags : sig
      type t =
      | Reserved_0
      | Hide_client_names
      | Kdc_follow_referrals

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

  module Checksum : sig
    type t =
      { cksumtype : Checksum_type.t
      ; checksum : Octet_string.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Checksum_type.Ast.t * Octet_string.Ast.t
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

  (** Host address, see {{:https://tools.ietf.org/html/rfc4120#section-5.2.5}rfc4120 Section 5.2.5 Host Address and Host Addresses} *)
  module Host_address : sig
    type t =
      { addr_type : Address_type.t
      ; address : Octet_string.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Address_type.Ast.t * Cstruct.t
  end

  (** Host addresses, see {{:https://tools.ietf.org/html/rfc4120#section-5.2.5}rfc4120 Section 5.2.5 Host Address and Host Addresses} *)
  module Host_addresses : sig
    type t = Host_address.t list
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Host_address.Ast.t list
  end

  (** Pre-authentication data types, see {{https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-4} Kerberos Pre-authentication and Typed Data, Last updated 2017-03-02} *)
  module Pa_data_type : sig
    module M : sig
      type t =
      | PA_TGS_REQ
      | PA_ENC_TIMESTAMP
      | PA_PW_SALT
      | Reserved_0
      | PA_ENC_UNIX_TIME
      | PA_SANDIA_SECUREID
      | PA_SESAME
      | PA_OSF_DCE
      | PA_CYBERSAFE_SECUREID
      | PA_AFS3_SALT
      | PA_ETYPE_INFO
      | PA_SAM_CHALLENGE
      | PA_SAM_RESPONSE
      | PA_PK_AS_REQ_OLD
      | PA_PK_AS_REP_OLD
      | PA_PK_AS_REQ
      | PA_PK_AS_REP
      | PA_PK_OCSP_RESPONSE
      | PA_ETYPE_INFO2
      | PA_USE_SPECIFIED_KVNO
      | PA_SVR_REFERRAL_INFO
      | PA_SAM_REDIRECT
      | PA_GET_FROM_TYPED_DATA
      | TD_PADATA
      | PA_SAM_ETYPE_INFO
      | PA_ALT_PRINC
      | PA_SERVER_REFERRAL
      | PA_SAM_CHALLENGE2
      | PA_SAM_RESPONSE2
      | PA_EXTRA_TGT
      | TD_PKINIT_CMS_CERTIFICATES
      | TD_KRB_PRINCIPAL
      | TD_KRB_REALM
      | TD_TRUSTED_CERTIFIERS
      | TD_CERTIFICATE_INDEX
      | TD_APP_DEFINED_ERROR
      | TD_REQ_NONCE
      | TD_REQ_SEQ
      | TD_DH_PARAMETERS
      | TD_CMS_DIGEST_ALGORITHMS
      | TD_CERT_DIGEST_ALGORITHMS
      | PA_PAC_REQUEST
      | PA_FOR_USER
      | PA_FOR_X509_USER
      | PA_FOR_CHECK_DUPS
      | PA_AS_CHECKSUM
      | PA_FX_COOKIE
      | PA_AUTHENTICATION_SET
      | PA_AUTH_SET_SELECTED
      | PA_FX_FAST
      | PA_FX_ERROR
      | PA_ENCRYPTED_CHALLENGE
      | PA_OTP_CHALLENGE
      | PA_OTP_REQUEST
      | PA_OTP_CONFIRM
      | PA_OTP_PIN_CHANGE
      | PA_EPAK_AS_REQ
      | PA_EPAK_AS_REP
      | PA_PKINIT_KX
      | PA_PKU2U_NAME
      | PA_REQ_ENC_PA_REP
      | PA_AS_FRESHNESS
      | PA_SUPPORTED_ETYPES
      | PA_EXTENDED_ERROR

      val alist : (t * int) list
    end

    include Asn1_intf.S with
          type t = M.t
      and type Ast.t = Krb_int32.Of_alist(M).Ast.t
  end

  (** Pre-authorization data, see {{:https://tools.ietf.org/html/rfc4120#section-5.2.7}rfc4120 Section 5.2.7 PA-DATA
   * the specific structure of padata_value depends on the padata_type.
   *)
  module Pa_data : sig
    type t =
      { padata_type : Pa_data_type.t
      ; padata_value : Octet_string.t
      } [@@deriving sexp]
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Pa_data_type.Ast.t * Cstruct.t
  end

  (** Authorization data, see {{:https://tools.ietf.org/html/rfc4120#section-5.2.6}rfc4120 Section 5.2.6 AuthorizationData}
   * the specific structure of ad_data depends on the ad_type.
   *)
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

  module As_req : sig
    type t =
      { padata : Pa_data.t list
      ; req_body : Kdc_req_body.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t =
              int (* pvno = 5 *)
            * int (* msg_type = Application_tag.int_of_t 'As_req *)
            * Pa_data.Ast.t list option (* Non-empty *)
            * Kdc_req_body.Ast.t
  end

  module Tgs_req : sig
    type t =
      { padata : Pa_data.t list
      ; req_body : Kdc_req_body.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t =
              int (* pvno = 5 *)
            * int (* msg_type = Application_tag.int_of_t 'Tgs_req *)
            * Pa_data.Ast.t list option (* Non-empty *)
            * Kdc_req_body.Ast.t
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
