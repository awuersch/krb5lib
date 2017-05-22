open Asn

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

  (** ASN.1 interface -- every message module matches this *)
  module Asn1_intf : sig

    (** Each ASN.1 type matches or extends this *)
    module type S = sig

      (** a primitive or record representation *)
      type t
  
      (** Abstract syntax tree, typed per asn1-combinators *)
      module Ast : sig

        (** A primitive, tuple, nested pair, or list.

            Tuples and nested pairs are equivalent.
            [SUGG] it's possible the tuple should be only a nested pair.
        *)
        type t

        (** an ASN.1 type, as per asn1-combinators package *)
        val asn : t Asn.t
      end
  
      (** marshalling *)
      val ast_of_t : t -> Ast.t

      (** de-marshalling *)
      val t_of_ast : Ast.t -> t

      (** serializing *)
      val sexp_of_t : t -> Sexplib.Sexp.t

      (** de-serializing *)
      val t_of_sexp : Sexplib.Sexp.t -> t
    end
  end

  (** Utility module -- module types and functors *)
  module Interfaces : sig

    (** variant type -> int map * string map *)
    module type ALIST = sig
      type t
      val alist : (t * int * string) list
    end

    (** Encoding and decoding *)
    module type Intable = sig
      type t
      val t_of_int : int -> t
      val int_of_t : t -> int
      val t_of_string : string -> t
      val string_of_t : t -> string
    end

    (** To set up sets *)
    module OrderedType_of_Intable (M : Intable) : sig
      type t = M.t
      val compare : t -> t -> int
    end

    (** Slower than a custom Intable implementation *)
    module Intable_of_alist (M : ALIST) : sig
      type t = M.t
      val t_of_int : int -> t
      val int_of_t : t -> int
      val t_of_string : string -> t
      val string_of_t : t -> string
    end
  end

  (** Utility msg.  ASN.1 Octet_string type. *)
  module Octet_string :
    Asn1_intf.S with type t = string and type Ast.t = Cstruct.t

  (** Utility msg.
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.1> Section KerberosString
  *)
  module Kerberos_string :
    Asn1_intf.S with type t = string and type Ast.t = string

  (** Utility msg.
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.4> Section Constrained Integer Types
  *)
  module Krb_int32 : sig
    include Asn1_intf.S with type t = int32 and type Ast.t = Z.t
    module Of_alist (M : Interfaces.ALIST) : Asn1_intf.S with type t = M.t
  end

  (** Utility msg.
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.4> Section Constrained Integer Types
  *)
  module Uint32 : sig
    include Asn1_intf.S with type t = int64 and type Ast.t = Z.t
  end

  (** Utility msg.
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.4> Section Constrained Integer Types
  *)
  module Microseconds : sig
    include Asn1_intf.S with type t = int32 and type Ast.t = Z.t
  end

  (** Utility msg.  Kerberos realm.
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.2> Section Realm and PrincipalName
  *)
  module Realm :
    Asn1_intf.S with type t = string and type Ast.t = string

  (** Utility msg.  Kerberos Time.
      ASN.1 GeneralizedTime with no fractional seconds

      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.3> Section KerberosTime
  *)
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

  (** Utility msg.  Host Address.
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.5> Section HostAddress and HostAddresses
  *)
  module Host_address : sig
    type t =
      { addr_type : Address_type.t
      ; address : Octet_string.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Address_type.Ast.t * Cstruct.t
  end

  (** Utility msg.  Host Addresses.
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.5> Section HostAddress and HostAddresses
  *)
  module Host_addresses : sig
    type t = Host_address.t list
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Host_address.Ast.t list
  end

  (** Utility msg.  Authorization Data.
    
      AuthorizationData is always used as an OPTIONAL field.
      It should not be empty.

      There are four authorization element types:
        {ul
        {- AD-IF-RELEVANT: ad-type = 1}
        {- AD-KDCIssued: ad-type = 4}
        {- AD-AND_OR: ad-type = 5}
        {- AD-MANDATORY-FOR-KDC: ad-type = 8}}

      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.6> Section AuthorizationData
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.6.1> Section IF-RELEVANT
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.6.2> Section KDCIssued
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.6.3> Section AND-OR
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.6.4> Section MANDATORY-FOR-KDC
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

  (** Utility msg.  Pre-authentication and Typed Data.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.7> Section PA-DATA.

      Pre-authentication data types:
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml> IANA Kerberos parameters
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-4> Kerberos Pre-authentication and Typed Data, Last updated 2017-03-02
  *)
  module Pa_data_type : sig
    module M : sig
      type t =
      | PA_TGS_REQ (** @see <https://tools.ietf.org/html/rfc4120> *)
      | PA_ENC_TIMESTAMP (** @see <https://tools.ietf.org/html/rfc4120> *)
      | PA_PW_SALT (** @see <https://tools.ietf.org/html/rfc4120> *)
      | Reserved_0 (** @see <https://tools.ietf.org/html/rfc6113> *)
      | PA_ENC_UNIX_TIME (** (deprecated) @see <https://tools.ietf.org/html/rfc4120> *)
      | PA_SANDIA_SECUREID (** @see <https://tools.ietf.org/html/rfc4120> *)
      | PA_SESAME (** @see <https://tools.ietf.org/html/rfc4120> *)
      | PA_OSF_DCE (** @see <https://tools.ietf.org/html/rfc4120> *)
      | PA_CYBERSAFE_SECUREID (** @see <https://tools.ietf.org/html/rfc4120> *)
      | PA_AFS3_SALT (** @see <https://tools.ietf.org/html/rfc3961> *)
      | PA_ETYPE_INFO (** @see <https://tools.ietf.org/html/rfc4120> *)
      | PA_SAM_CHALLENGE (** @see <https://tools.ietf.org/html/draft-ietf-cat-kerberos-passwords-04> *)
      | PA_SAM_RESPONSE (** @see <https://tools.ietf.org/html/draft-ietf-cat-kerberos-passwords-04> *)
      | PA_PK_AS_REQ_OLD (** @see <https://tools.ietf.org/html/draft-ietf-cat-kerberos-pk-init-09> *)
      | PA_PK_AS_REP_OLD (** @see <https://tools.ietf.org/html/draft-ietf-cat-kerberos-pk-init-09> *)
      | PA_PK_AS_REQ (** @see <https://tools.ietf.org/html/rfc4556> *)
      | PA_PK_AS_REP (** @see <https://tools.ietf.org/html/rfc4556> *)
      | PA_PK_OCSP_RESPONSE (** @see <https://tools.ietf.org/html/rfc4557> *)
      | PA_ETYPE_INFO2 (** @see <https://tools.ietf.org/html/rfc4120> *)
      | PA_USE_SPECIFIED_KVNO (** @see <https://tools.ietf.org/html/rfc4120> *)
      | PA_SVR_REFERRAL_INFO (** @see <https://tools.ietf.org/html/rfc6806> *)
      | PA_SAM_REDIRECT (** @see <https://tools.ietf.org/html/rfc4120> *)
      | PA_GET_FROM_TYPED_DATA (** @see <https://tools.ietf.org/html/rfc4120> *)
      | TD_PADATA (** @see <https://tools.ietf.org/html/rfc4120> *)
      | PA_SAM_ETYPE_INFO (** @see <https://tools.ietf.org/html/draft-ietf-krb-wg-kerberos-sam-03> *)
      | PA_ALT_PRINC (** @see <https://tools.ietf.org/html/draft-ietf-krb-wg-hw-auth-04> *)
      | PA_SERVER_REFERRAL (** @see <https://tools.ietf.org/html/draft-ietf-krb-wg-kerberos-referrals-11> *)
      | PA_SAM_CHALLENGE2 (** @see <https://tools.ietf.org/html/draft-ietf-krb-wg-kerberos-sam-03> *)
      | PA_SAM_RESPONSE2 (** @see <https://tools.ietf.org/html/draft-ietf-krb-wg-kerberos-sam-03> *)
      | PA_EXTRA_TGT (** @see <https://tools.ietf.org/html/rfc6113> *)
      | TD_PKINIT_CMS_CERTIFICATES (** @see <https://tools.ietf.org/html/rfc4556> *)
      | TD_KRB_PRINCIPAL (** @see <https://tools.ietf.org/html/rfc6113> *)
      | TD_KRB_REALM (** @see <https://tools.ietf.org/html/rfc6113> *)
      | TD_TRUSTED_CERTIFIERS (** @see <https://tools.ietf.org/html/rfc4556> *)
      | TD_CERTIFICATE_INDEX (** @see <https://tools.ietf.org/html/rfc4556> *)
      | TD_APP_DEFINED_ERROR (** @see <https://tools.ietf.org/html/rfc6113> *)
      | TD_REQ_NONCE (** @see <https://tools.ietf.org/html/rfc6113> *)
      | TD_REQ_SEQ (** @see <https://tools.ietf.org/html/rfc6113> *)
      | TD_DH_PARAMETERS (** @see <https://tools.ietf.org/html/rfc4556> *)
      | TD_CMS_DIGEST_ALGORITHMS (** @see <https://tools.ietf.org/html/draft-ietf-krb-wg-pkinit-alg-agility> *)
      | TD_CERT_DIGEST_ALGORITHMS (** @see <https://tools.ietf.org/html/draft-ietf-krb-wg-pkinit-alg-agility> *)
      | PA_PAC_REQUEST (** @see <http://msdn2.microsoft.com/en_us/library/cc206927.aspx> *)
      | PA_FOR_USER (** @see <http://msdn2.microsoft.com/en_us/library/cc206927.aspx> *)
      | PA_FOR_X509_USER (** @see <http://msdn2.microsoft.com/en_us/library/cc206927.aspx> *)
      | PA_FOR_CHECK_DUPS (** @see <http://msdn2.microsoft.com/en_us/library/cc206927.aspx> *)
      | PA_AS_CHECKSUM (** @see <http://msdn2.microsoft.com/en_us/library/cc206927.aspx> *)
      | PA_FX_COOKIE (** @see <https://tools.ietf.org/html/rfc6113> *)
      | PA_AUTHENTICATION_SET (** @see <https://tools.ietf.org/html/rfc6113> *)
      | PA_AUTH_SET_SELECTED (** @see <https://tools.ietf.org/html/rfc6113> *)
      | PA_FX_FAST (** @see <https://tools.ietf.org/html/rfc6113> *)
      | PA_FX_ERROR (** @see <https://tools.ietf.org/html/rfc6113> *)
      | PA_ENCRYPTED_CHALLENGE (** @see <https://tools.ietf.org/html/rfc6113> *)
      | PA_OTP_CHALLENGE (** @see <https://tools.ietf.org/html/rfc6560> *)
      | PA_OTP_REQUEST (** @see <https://tools.ietf.org/html/rfc6560> *)
      | PA_OTP_CONFIRM (** @see <https://tools.ietf.org/html/rfc6560> *)
      | PA_OTP_PIN_CHANGE (** @see <https://tools.ietf.org/html/rfc6560> *)
      | PA_EPAK_AS_REQ (** @see <https://tools.ietf.org/html/rfc6113> *)
      | PA_EPAK_AS_REP (** @see <https://tools.ietf.org/html/rfc6113> *)
      | PA_PKINIT_KX (** @see <https://tools.ietf.org/html/rfc8062> *)
      | PA_PKU2U_NAME (** @see <https://tools.ietf.org/html/draft-zhu-pku2u> *)
      | PA_REQ_ENC_PA_REP (** @see <https://tools.ietf.org/html/6806> *)
      | PA_AS_FRESHNESS (** @see <https://tools.ietf.org/html/rfc8070> *)
      | PA_SUPPORTED_ETYPES (** @see <http://msdn2.microsoft.com/en_us/library/cc206927.aspx> *)
      | PA_EXTENDED_ERROR (** @see <http://msdn2.microsoft.com/en_us/library/cc206927.aspx> *)

      val alist : (t * int * string) list
    end

    include Asn1_intf.S with
          type t = M.t
      and type Ast.t = Krb_int32.Of_alist(M).Ast.t
  end

  (** Utility msg.  Pre-authentication Data.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.7> Section PA-DATA.
  *)
  module Pa_data : sig
    type t =
      { padata_type : Pa_data_type.t   (** {!module:Pa_data_type.t} *)
      ; padata_value : Octet_string.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Pa_data_type.Ast.t * Cstruct.t
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

      val alist : (t * int * string) list
    end

    include Asn1_intf.S with
          type t = M.t
      and type Ast.t = Krb_int32.Of_alist(M).Ast.t
  end

  (** Encryption Type.
      @see <https://tools.ietf.org/html/rfc3961> RFC
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml> IANA Kerberos parameters
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-1> Kerberos Encryption Type Numbers, LasChecksum typet updated 2017-03-02
  *)
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
      val alist : (t * int * string) list
    end

    include Asn1_intf.S with
          type t = M.t
      and type Ast.t = Krb_int32.Of_alist(M).Ast.t
  end

  (** Checksum type.
      @see <https://tools.ietf.org/html/rfc3961> RFC
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml> IANA Kerberos parameters
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-2> Kerberos Checksum Type Numbers, Last updated 2017-03-02
  *)
  module Checksum_type : sig
    module M : sig
      type t =
      | Reserved_0 (** @see <https://tools.ietf.org/html/rfc3961#section-6.1.3> *)
      | CRC32 (** @see <https://tools.ietf.org/html/rfc3961#section-6.1.3> *)
      | Rsa_md4 (** @see <https://tools.ietf.org/html/rfc3961#section-6.1.2> *)
      | Rsa_md4_des (** @see <https://tools.ietf.org/html/rfc3961#section-6.2.5> *)
      | Des_mac (** @see <https://tools.ietf.org/html/rfc3961#section-6.2.7> *)
      | Des_mac_k (** @see <https://tools.ietf.org/html/rfc3961#section-6.2.8> *)
      | Rsa_md4_des_k (** @see <https://tools.ietf.org/html/rfc3961#section-6.2.6> *)
      | Rsa_md5 (** @see <https://tools.ietf.org/html/rfc3961#section-6.1.1> *)
      | Rsa_md5_des (** @see <https://tools.ietf.org/html/rfc3961#section-6.2.4> *)
      | Rsa_md5_des3
      | Sha1_unkeyed_0
      | Hmac_sha1_des3_kd (** @see <https://tools.ietf.org/html/rfc3961#section-6.3> *)
      | Hmac_sha1_des3
      | Sha1_unkeyed_1
      | Hmac_sha1_96_aes128 (** @see <https://tools.ietf.org/html/rfc3962> *)
      | Hmac_sha1_96_aes256 (** @see <https://tools.ietf.org/html/rfc3962> *)
      | Cmac_camellia128 (** @see <https://tools.ietf.org/html/rfc6803> *)
      | Cmac_camellia256 (** @see <https://tools.ietf.org/html/rfc6803> *)
      | Hmac_sha256_128_aes128 (** @see <https://tools.ietf.org/html/rfc8009> *)
      | Hmac_sha256_192_aes256 (** @see <https://tools.ietf.org/html/rfc8009> *)
      | Reserved_1 (** @see <https://tools.ietf.org/html/rfc1964> *)

      val alist : (t * int * string) list
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

      val alist : (t * int * string) list
    end

    include Asn1_intf.S with
          type t = M.t
      and type Ast.t = Krb_int32.Of_alist(M).Ast.t
  end

  (** TCP Extensions.
      @see <https://tools.ietf.org/html/rfc5021> RFC
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml> IANA Kerberos parameters
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-3> Kerberos TCP Extensions, Last updated 2017-03-02
  *)
  module Tcp_extension : sig
    module M : sig
      type t =
      | Krb5_over_TLS (** @see <https://tools.ietf.org/html/rfc6251> *)
      | Reserved_30 (** @see <https://tools.ietf.org/html/rfc5021> *)

      val alist : (t * int * string) list
    end

    include Asn1_intf.S with
          type t = M.t
      and type Ast.t = Krb_int32.Of_alist(M).Ast.t
  end

  (** FAST Armor Type.
      @see <https://tools.ietf.org/html/rfc6113> RFC
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml> IANA Kerberos parameters
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-5> FAST Armor Types, Last updated 2017-03-02
  *)
  module Fast_armor_type : sig
    module M : sig
      type t =
      | Reserved_0 (** @see <https://tools.ietf.org/html/rfc6113> *)
      | FX_FAST_ARMOR_AP_REQUEST (** @see <https://tools.ietf.org/html/rfc6113> *)

      val alist : (t * int * string) list
    end

    include Asn1_intf.S with
          type t = M.t
      and type Ast.t = Krb_int32.Of_alist(M).Ast.t
  end

  (** Transport Type.
      @see <https://tools.ietf.org/html/rfc6784> RFC
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml> IANA Kerberos parameters
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-9> Kerberos Message Transport Types, Last updated 2017-03-02
  *)
  module Transport_type : sig
    module M : sig
      type t =
      | Reserved_0 (** @see <https://tools.ietf.org/html/rfc6784> *)
      | UDP (** @see <https://tools.ietf.org/html/rfc6784> *)
      | TCP (** @see <https://tools.ietf.org/html/rfc6784> *)
      | TLS (** @see <https://tools.ietf.org/html/rfc6784> *)

      val alist : (t * int * string) list
    end

    include Asn1_intf.S with
          type t = M.t
      and type Ast.t = Krb_int32.Of_alist(M).Ast.t
  end

  module Ticket_flags : sig
    module Flags : sig
      type t =
      | Reserved_0
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

      val alist : (t * int * string) list
      module Encoding_options : sig
        val min_bits : int
      end
    end

    module FlagSet : Set.S

    include Asn1_intf.S with
         type t = FlagSet.t
     and type Ast.t = bool array
  end

  module Ap_options : sig
    module Flags : sig
      type t =
      | Reserved_0
      | Use_session_key
      | Mutual_required

      val alist : (t * int * string) list
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
      | Reserved_0
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

      val alist : (t * int * string) list
      module Encoding_options : sig
        val min_bits : int
      end
    end

    module FlagSet : Set.S

    include Asn1_intf.S with
         type t = FlagSet.t
     and type Ast.t = bool array
  end

  (** FAST Options.
      @see <https://tools.ietf.org/html/rfc6113> RFC
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml> IANA Kerberos parameters
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-6> FAST Options, Last updated 2017-03-02
  *)
  module Fast_options : sig
    module Flags : sig
      type t =
      | Reserved_0 (** @see <https://tools.ietf.org/html/rfc6113> *)
      | Hide_client_names (** @see <https://tools.ietf.org/html/rfc6113> *)
      | Kdc_follow_referrals (** @see <https://tools.ietf.org/html/rfc6113> *)

      val alist : (t * int * string) list
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

  (** Last req, see {{:https://tools.ietf.org/html/rfc4120#section-5.4.2}rfc4120 Section 5.4.2 KRB_KDC_REP Definition} *)
  module Last_req_inst : sig
    type t =
      { lr_type : Krb_int32.t
      ; lr_value : Kerberos_time.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Krb_int32.Ast.t * Kerberos_time.Ast.t
  end

  (** Last req, see {{:https://tools.ietf.org/html/rfc4120#section-5.4.2}rfc4120 Section 5.4.2 KRB_KDC_REP Definition} *)
  module Last_req : sig
    type t = Last_req_inst.t list
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Last_req_inst.Ast.t list
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
            *  Authorization_data.Ast.t option)))))))))
  end

  module Enc_kdc_rep_part : sig
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
      }
    module Ast : sig
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
 
      val app_asn : Application_tag.t -> t Asn.t
    end
    val ast_of_t : t -> Ast.t
    val t_of_ast : Ast.t -> t
    val sexp_of_t : t -> Sexplib.Sexp.t
    val t_of_sexp : Sexplib.Sexp.t -> t
  end

  module Enc_as_rep_part : sig
    type t = Enc_kdc_rep_part.t
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Enc_kdc_rep_part.Ast.t
  end

  module Enc_tgs_rep_part : sig
    type t = Enc_kdc_rep_part.t
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Enc_kdc_rep_part.Ast.t
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
            Z.t * Realm.Ast.t * Principal_name.Ast.t * Encrypted_data.Ast.t
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

  module Ap_req : sig
    type t =
      { ap_options : Ap_options.t
      ; ticket : Ticket.t
      ; authenticator : Encrypted_data.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t =
            Z.t * Z.t * Ap_options.Ast.t * Ticket.Ast.t * Encrypted_data.Ast.t
  end

  module Authenticator : sig
    type t =
      { crealm : Realm.t
      ; cname : Principal_name.t
      ; cksum : Checksum.t option
      ; cusec : Microseconds.t
      ; ctime : Kerberos_time.t
      ; subkey : Encryption_key.t option
      ; seq_number : Uint32.t option
      ; authorization_data : Authorization_data.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t =
              Z.t
            * (Realm.Ast.t
            * (Principal_name.Ast.t
            * (Checksum.Ast.t option
            * (Microseconds.Ast.t
            * (Kerberos_time.Ast.t
            * (Encryption_key.Ast.t option
            * (Uint32.Ast.t option
            *  Authorization_data.Ast.t option)))))))
  end

  module Enc_ap_rep_part : sig
    type t =
      { ctime : Kerberos_time.t
      ; cusec : Microseconds.t
      ; subkey : Encryption_key.t option
      ; seq_number : Uint32.t option
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t =
              Kerberos_time.Ast.t
            * Microseconds.Ast.t
            * Encryption_key.Ast.t option
            * Uint32.Ast.t option
  end

  module Ap_rep : sig
    type t =
      { enc_part : Encrypted_data.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Z.t * Z.t * Encrypted_data.Ast.t
  end

  module Kdc_rep : sig
    type t =
      { padata   : Pa_data.t list
      ; crealm   : Realm.t
      ; cname    : Principal_name.t
      ; ticket   : Ticket.t
      ; enc_part : Encrypted_data.t
      }
    module Ast : sig
      type t =
          Z.t (* pvno - 5 *)
        * (Z.t (* msg_type *)
        * (Pa_data.Ast.t list option (* Non-empty *)
        * (Realm.Ast.t
        * (Principal_name.Ast.t
        * (Ticket.Ast.t
        *  Encrypted_data.Ast.t)))))
      val asn : t Asn.t
    end
    val app_ast_of_t : Application_tag.t -> t -> Ast.t
    val t_of_ast : Ast.t -> t
    val sexp_of_t : t -> Sexplib.Sexp.t
    val t_of_sexp : Sexplib.Sexp.t -> t
  end

  module Kdc_req : sig
    type t =
      { padata : Pa_data.t list
      ; req_body : Kdc_req_body.t
      }
    module Ast : sig
      type t =
          Z.t
        * Z.t
        * Pa_data.Ast.t list option
        * Kdc_req_body.Ast.t
      val asn : t Asn.t
    end
    val app_ast_of_t : Application_tag.t -> t -> Ast.t
    val t_of_ast : Ast.t -> t
    val sexp_of_t : t -> Sexplib.Sexp.t
    val t_of_sexp : Sexplib.Sexp.t -> t
  end

  module As_rep : sig
    type t = Kdc_rep.t
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Kdc_rep.Ast.t
  end

  module As_req : sig
    type t = Kdc_req.t
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Kdc_req.Ast.t
  end

  module Tgs_rep : sig
    type t = Kdc_rep.t
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Kdc_rep.Ast.t
  end

  module Tgs_req : sig
    type t = Kdc_req.t
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Kdc_req.Ast.t
  end

  module Krb_safe_body : sig
    type t =
      { user_data : Octet_string.t
      ; timestamp : Kerberos_time.t option
      ; usec : Microseconds.t option
      ; seq_number : Uint32.t option
      ; s_address : Host_address.t
      ; r_address : Host_address.t option
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t =
            Octet_string.Ast.t
            * (Kerberos_time.Ast.t option
            * (Microseconds.Ast.t option
            * (Uint32.Ast.t option
            * (Host_address.Ast.t
            *  Host_address.Ast.t option))))
  end

  module Krb_safe : sig
    type t =
      { safe_body : Krb_safe_body.t
      ; cksum : Checksum.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Z.t * Z.t * Krb_safe_body.Ast.t * Checksum.Ast.t
  end

  module Krb_priv : sig
    type t =
      { enc_part : Encrypted_data.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Z.t * Z.t * Encrypted_data.Ast.t
  end

  (** structurally same except for application tag *)
  module Enc_krb_priv_part : sig
    type t = Krb_safe_body.t
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Krb_safe_body.Ast.t
  end

  module Krb_cred : sig
    type t =
      { tickets : Ticket.t list
      ; enc_part : Encrypted_data.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Z.t * Z.t * Ticket.Ast.t list * Encrypted_data.Ast.t
  end

  module Krb_cred_info : sig
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
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t =
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
  end

  module Enc_krb_cred_part : sig
    type t =
      { ticket_info : Krb_cred_info.t list
      ; nonce : Uint32.t option
      ; timestamp : Kerberos_time.t option
      ; usec : Microseconds.t option
      ; s_address : Host_address.t option
      ; r_address : Host_address.t option
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t =
            Krb_cred_info.Ast.t list
            * (Uint32.Ast.t option
            * (Kerberos_time.Ast.t option
            * (Microseconds.Ast.t option
            * (Host_address.Ast.t option
            *  Host_address.Ast.t option))))
  end

  module Krb_error : sig
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
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t =
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
  end

  module Method_data : sig
    type t = { method_data : Pa_data.t list }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Pa_data.Ast.t list
  end

  module Typed_data : sig
    module Datum : sig
      type t =
        { data_type : Krb_int32.t
        ; data_value : Octet_string.t option
        }
      include Asn1_intf.S with
            type t := t
        and type Ast.t = Krb_int32.Ast.t * Octet_string.Ast.t option
    end

    type t = Datum.t list
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Datum.Ast.t list
  end

  module Pa_enc_ts_enc : sig
    type t =
      { patimestamp : Kerberos_time.t
      ; pausec : Microseconds.t option
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Kerberos_time.Ast.t * Microseconds.Ast.t option
  end

  module Etype_info_entry : sig
    type t =
      { etype : Krb_int32.t
      ; salt : Octet_string.t option
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Krb_int32.Ast.t * Octet_string.Ast.t option
  end

  module Etype_info : sig
    type t = Etype_info_entry.t list
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Etype_info_entry.Ast.t list
  end

  module Etype_info2_entry : sig
    type t =
      { etype : Krb_int32.t
      ; salt : Kerberos_string.t option
      ; s2kparams : Octet_string.t option
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t =
              Krb_int32.Ast.t
            * Kerberos_string.Ast.t option
            * Octet_string.Ast.t option
  end

  module Etype_info2 : sig
    type t = Etype_info2_entry.t list
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Etype_info2_entry.Ast.t list
  end

  module Ad_kdcissued : sig
    type t =
      { ad_checksum : Checksum.t
      ; i_realm : Realm.t option
      ; i_sname : Principal_name.t option
      ; elements : Authorization_data.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t =
              Checksum.Ast.t
            * Realm.Ast.t option
            * Principal_name.Ast.t option
            * Authorization_data.Ast.t
  end

  module Ad_and_or : sig
    type t =
      { condition_count : Krb_int32.t
      ; elements : Authorization_data.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Krb_int32.Ast.t * Authorization_data.Ast.t
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
