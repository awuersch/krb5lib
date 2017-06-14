(*---------------------------------------------------------------------------
   Copyright (c) 2017 Tony Wuersch. All rights reserved.
   Copyright (c) 2015 Brandon Bohrer. All rights reserved.
   See LICENSE.md *)

(** Kerberos5 messages and ASN.1 syntaxes as O'Caml records and types.

    Embeds
    {b References}
    {ul
    {- rfc4120 Appendix A. {{:https://tools.ietf.org/html/rfc4120#appendixA} The
         Kerberos Authentication Service (V5)}, Appendix A. ASN.1 module}
    {- rfc4120. {{:https://tools.ietf.org/html/rfc4120} The
         Kerberos Authentication Service (V5)}}
    {- rfc4537.  {{:https://tools.ietf.org/html/rfc4537} Kerberos
         Cryptosystem Negotiation Extension}}
    {- rfc5021.  {{:https://tools.ietf.org/html/rfc5021} Extended Kerberos
         Version 5 Key Distribution Center (KDC) Exchanges over TCP}}
    {- rfc5896  {{:https://tools.ietf.org/html/rfc5896} Generic Security Service
         Application Program Interface (GSS-API):
         Delegate if Approved by Policy}}
    }
    
    {e %%VERSION%% — {{:%%PKG_HOMEPAGE%% }homepage}}

    X509 encoding, generation, and validation.

    [X509] is a module for handling X.509 certificates, as described
    in {{:https://tools.ietf.org/html/rfc5280}RFC 5280}.  X.509
    describes a hierarchical public key infrastructure, where all
    trust is delegated to certificate authorities (CA).  The task of a
    CA is to sign certificate signing requests (CSR), which turns them
    into certificates, after verification that the requestor is
    eligible.

    An X.509 certificate is an authentication token: a public key, a
    subject (e.g. server name), a validity period, optionally a
    purpose (usage), and various other optional {{!Extension}Extensions}.

    The public keys of trusted CAs are distributed with the software,
    or configured manually.  When an endpoint connects, it has to
    present its certificate chain, which are pairwise signed
    certificates.  This chain is verified: the signatures have to be
    valid, the last certificate must be signed by a trusted CA, the
    name has to match the expected name, all certificates must be
    valid at the current time, and the purpose of each certificate
    must match its usage.  An alternative validator checks that the
    hash of the server certificate matches the given hash.

    This module provides {{!Encoding}parsers and unparsers} (PEM
    encoding) of ASN.1 encoded X.509 certificates, public and private
    RSA keys ({{:http://tools.ietf.org/html/rfc5208}PKCS 8, RFC 5208}),
    and certificate signing requests
    ({{:http://tools.ietf.org/html/rfc2986}PKCS 10, RFC 2986}) (both
    require parts of {{:https://tools.ietf.org/html/rfc2985}PKCS9,
    RFC 2985}), {{!Validation} validation} of certificates, and
    construction of {{!Authenticator} authenticators}.  Name
    validation, as defined in
    {{:https://tools.ietf.org/html/rfc6125}RFC 6125}, is also
    implemented.  The {{!CA}CA} module provides functionality to
    create and sign CSR.

    Missing is the handling of certificate revocation lists, online
    certificate status protocol, some X.509v3 extensions (such as
    policy and name constraints).  The only supported key type is
    RSA.

    {e %%VERSION%% - {{:%%PKG_HOMEPAGE%% }homepage}} *)

(** {1 Krb5lib} Krb5 message types *)
module Msg : sig

  (** ASN.1 interface -- every message module matches this *)
  module Asn1_intf : sig

    (** Each ASN.1 type matches or extends this *)
    module type S = sig

      (** a primitive or record representation *)
      type t
  
      (** an abstract syntax tree, typed per asn1-combinators *)
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

  (** Utility msg.  Principal name types.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-6.2> Section Principal Names
  *)
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

  (** Utility msg.  Principal name.
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.2> Section Realm and PrincipalName
  *)
  module Principal_name : sig
    type t =
      { name_type : Name_type.t
      ; name_string : Kerberos_string.t list
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Name_type.Ast.t * Kerberos_string.Ast.t list
  end

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

  (** Utility msg.  Address Type.
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.5> HostAddress and HostAddresses
      @see <https://tools.ietf.org/html/rfc4120#section-7.5.3> Address Types.
  *)
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

      Authorization element types:
        {ul
        {- AD_IF_RELEVANT. ad-type = 1, rfc4120}
        {- AD_KDCIssued. ad-type = 4, rfc4120}
        {- AD_AND_OR. ad-type = 5, rfc4120}
        {- AD_MANDATORY_FOR_KDC. ad-type = 8, rfc4120}
        {- AD_ETYPE_NEGOTIATION. ad-type = 129, rfc4537}}

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

  (** Utility msg.  AD-AND-OR authorization data value.

      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.6> Section AuthorizationData
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.6.3> Section AND-OR.
  *)
  module Ad_and_or : sig
    type t =
      { condition_count : Krb_int32.t
      ; elements : Authorization_data.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Krb_int32.Ast.t * Authorization_data.Ast.t
  end

  (** Utility msg.  AD-KDCIssued authorization data value.

      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.6> Section AuthorizationData
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.6.2> Section AD-KDC-ISSUED.
  *)
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

  (** Utility msg.  Pre-authentication and Typed Data.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.7> Section PA-DATA.

      Pre-authentication data types:
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml> IANA Kerberos parameters
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-4> Kerberos Pre-authentication and Typed Data, Last updated 2017-03-02
  *)
  module Pa_data_type : sig
    module M : sig

      (**
        {b References}
        {ul
          {- IETF. {{:https://tools.ietf.org/html/} RFC prefix link.}}
          {- MSFT. {{:http://msdn2.microsoft.com/en_us/library/cc206927.aspx} MSFT link.}}
        }
       *)
      type t =
      | PA_TGS_REQ (** IETF rfc4120 *)
      | PA_ENC_TIMESTAMP (** IETF rfc4120 *)
      | PA_PW_SALT (** IETF rfc4120 *)
      | Reserved_0 (** IETF rfc6113 *)
      | PA_ENC_UNIX_TIME (** IETF rfc4120 *)
      | PA_SANDIA_SECUREID (** IETF rfc4120 *)
      | PA_SESAME (** IETF rfc4120 *)
      | PA_OSF_DCE (** IETF rfc4120 *)
      | PA_CYBERSAFE_SECUREID (** IETF rfc4120 *)
      | PA_AFS3_SALT (** IETF rfc3961 *)
      | PA_ETYPE_INFO (** IETF rfc4120 *)
      | PA_SAM_CHALLENGE (** IETF draft-ietf-cat-kerberos-passwords-04 *)
      | PA_SAM_RESPONSE (** IETF draft-ietf-cat-kerberos-passwords-04 *)
      | PA_PK_AS_REQ_OLD (** IETF draft-ietf-cat-kerberos-pk-init-09 *)
      | PA_PK_AS_REP_OLD (** IETF draft-ietf-cat-kerberos-pk-init-09 *)
      | PA_PK_AS_REQ (** IETF rfc4556 *)
      | PA_PK_AS_REP (** IETF rfc4556 *)
      | PA_PK_OCSP_RESPONSE (** IETF rfc4557 *)
      | PA_ETYPE_INFO2 (** IETF rfc4120 *)
      | PA_USE_SPECIFIED_KVNO (** IETF rfc4120 *)
      | PA_SVR_REFERRAL_INFO (** IETF rfc6806 *)
      | PA_SAM_REDIRECT (** IETF rfc4120 *)
      | PA_GET_FROM_TYPED_DATA (** IETF rfc4120 *)
      | TD_PADATA (** IETF rfc4120 *)
      | PA_SAM_ETYPE_INFO (** IETF draft-ietf-krb-wg-kerberos-sam-03 *)
      | PA_ALT_PRINC (** IETF draft-ietf-krb-wg-hw-auth-04 *)
      | PA_SERVER_REFERRAL (** IETF draft-ietf-krb-wg-kerberos-referrals-11 *)
      | PA_SAM_CHALLENGE2 (** IETF draft-ietf-krb-wg-kerberos-sam-03 *)
      | PA_SAM_RESPONSE2 (** IETF draft-ietf-krb-wg-kerberos-sam-03 *)
      | PA_EXTRA_TGT (** IETF rfc6113 *)
      | TD_PKINIT_CMS_CERTIFICATES (** IETF rfc4556 *)
      | TD_KRB_PRINCIPAL (** IETF rfc6113 *)
      | TD_KRB_REALM (** IETF rfc6113 *)
      | TD_TRUSTED_CERTIFIERS (** IETF rfc4556 *)
      | TD_CERTIFICATE_INDEX (** IETF rfc4556 *)
      | TD_APP_DEFINED_ERROR (** IETF rfc6113 *)
      | TD_REQ_NONCE (** IETF rfc6113 *)
      | TD_REQ_SEQ (** IETF rfc6113 *)
      | TD_DH_PARAMETERS (** IETF rfc4556 *)
      | TD_CMS_DIGEST_ALGORITHMS (** IETF draft-ietf-krb-wg-pkinit-alg-agility *)
      | TD_CERT_DIGEST_ALGORITHMS (** IETF draft-ietf-krb-wg-pkinit-alg-agility *)
      | PA_PAC_REQUEST (** MSFT *)
      | PA_FOR_USER (** MSFT *)
      | PA_FOR_X509_USER (** MSFT *)
      | PA_FOR_CHECK_DUPS (** MSFT *)
      | PA_AS_CHECKSUM (** MSFT *)
      | PA_FX_COOKIE (** IETF rfc6113 *)
      | PA_AUTHENTICATION_SET (** IETF rfc6113 *)
      | PA_AUTH_SET_SELECTED (** IETF rfc6113 *)
      | PA_FX_FAST (** IETF rfc6113 *)
      | PA_FX_ERROR (** IETF rfc6113 *)
      | PA_ENCRYPTED_CHALLENGE (** IETF rfc6113 *)
      | PA_OTP_CHALLENGE (** IETF rfc6560 *)
      | PA_OTP_REQUEST (** IETF rfc6560 *)
      | PA_OTP_CONFIRM (** IETF rfc6560 *)
      | PA_OTP_PIN_CHANGE (** IETF rfc6560 *)
      | PA_EPAK_AS_REQ (** IETF rfc6113 *)
      | PA_EPAK_AS_REP (** IETF rfc6113 *)
      | PA_PKINIT_KX (** IETF rfc8062 *)
      | PA_PKU2U_NAME (** IETF draft-zhu-pku2u *)
      | PA_REQ_ENC_PA_REP (** IETF 6806 *)
      | PA_AS_FRESHNESS (** IETF rfc8070 *)
      | PA_SUPPORTED_ETYPES (** MSFT *)
      | PA_EXTENDED_ERROR (** MSFT *)

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
      { padata_type : Pa_data_type.t
      ; padata_value : Octet_string.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Pa_data_type.Ast.t * Cstruct.t
  end

  (** Encryption Type.
      @see <https://tools.ietf.org/html/rfc3961> RFC
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml> IANA Kerberos parameters
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-1> Kerberos Encryption Type Numbers, LastChecksum type updated 2017-03-02
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

  (** Utility msg.  Encryption Key.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.9> Section Cryptosystem-Related Types.
  *)
  module Encryption_key : sig
    type t =
      { keytype : Encryption_type.t
      ; keyvalue : Octet_string.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Encryption_type.Ast.t * Octet_string.Ast.t
  end

  (** Utility msg.  Encrypted Data.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.9> Section Cryptosystem-Related Types.
  *)
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

  (** Checksum type.
      @see <https://tools.ietf.org/html/rfc3961> RFC
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml> IANA Kerberos parameters
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-2> Kerberos Checksum Type Numbers, Last updated 2017-03-02
  *)
  module Checksum_type : sig
    module M : sig

      (**
        {b References}
        {ul
          {- IETF. {{:https://tools.ietf.org/html/} RFC prefix link.}}
        }
       *)
      type t =
      | Reserved_0 (** IETF rfc3961#section-6.1.3 *)
      | CRC32 (** IETF rfc3961#section-6.1.3 *)
      | Rsa_md4 (** IETF rfc3961#section-6.1.2 *)
      | Rsa_md4_des (** IETF rfc3961#section-6.2.5 *)
      | Des_mac (** IETF rfc3961#section-6.2.7 *)
      | Des_mac_k (** IETF rfc3961#section-6.2.8 *)
      | Rsa_md4_des_k (** IETF rfc3961#section-6.2.6 *)
      | Rsa_md5 (** IETF rfc3961#section-6.1.1 *)
      | Rsa_md5_des (** IETF rfc3961#section-6.2.4 *)
      | Rsa_md5_des3
      | Sha1_unkeyed_0
      | Hmac_sha1_des3_kd (** IETF rfc3961#section-6.3 *)
      | Hmac_sha1_des3
      | Sha1_unkeyed_1
      | Hmac_sha1_96_aes128 (** IETF rfc3962 *)
      | Hmac_sha1_96_aes256 (** IETF rfc3962 *)
      | Cmac_camellia128 (** IETF rfc6803 *)
      | Cmac_camellia256 (** IETF rfc6803 *)
      | Hmac_sha256_128_aes128 (** IETF rfc8009 *)
      | Hmac_sha256_192_aes256 (** IETF rfc8009 *)
      | Reserved_1 (** IETF rfc1964 *)

      val alist : (t * int * string) list
    end

    include Asn1_intf.S with
          type t = M.t
      and type Ast.t = Krb_int32.Of_alist(M).Ast.t
  end

  (** Utility msg.  Checksum.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.2.9> Section Cryptosystem-Related Types.
  *)
  module Checksum : sig
    type t =
      { cksumtype : Checksum_type.t
      ; checksum : Octet_string.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Checksum_type.Ast.t * Octet_string.Ast.t
  end

  (** Utility msg.  Application tags.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.10> Section Application Tag Numbers
  *)
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

  (** Tickets msg.  Ticket Flags.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.3> Section Tickets.
  *)
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

  (** Tickets msg.  Transited Encoding.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.3> Section Tickets.
  *)
  module Transited_encoding : sig
    type t =
      { tr_type : Krb_int32.t
      ; contents : Octet_string.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Krb_int32.Ast.t * Octet_string.Ast.t
  end

  (** Tickets msg.  Ticket.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.3> Section Tickets.
  *)
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

  (** Tickets msg.  Encrypted Ticket Part.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.3> Section Tickets.
  *)
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

  (** AS and TGS Exchanges.  KDC Options.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.4.1> Section KRB_KDC_REQ Definition.
  *)
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

  (** AS and TGS Exchanges.  KDC-REQ body.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.4.1> Section KRB_KDC_REQ Definition.
  *)
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

  (** AS and TGS Exchanges.  KDC-REQ.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.4.1> Section KRB_KDC_REQ Definition.
  *)
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

  (** AS and TGS Exchanges.  AS-REQ.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.1> Section The Authentication Service Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.4.1> Section KRB_KDC_REQ Definition.
  *)
  module As_req : sig
    type t = Kdc_req.t
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Kdc_req.Ast.t
  end

  (** AS and TGS Exchanges.  TGS-REQ.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.3> The Ticket-Granting Service (TGS) Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.4.1> Section KRB_KDC_REQ Definition.
  *)
  module Tgs_req : sig
    type t = Kdc_req.t
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Kdc_req.Ast.t
  end

  (** AS and TGS Exchanges.  KDC-REP.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.4.2> Section KRB_KDC_REP Definition.
  *)
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

  (** AS and TGS Exchanges.  AS-REP.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.1> Section The Authentication Service Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.4.2> Section KRB_KDC_REP Definition.
  *)
  module As_rep : sig
    type t = Kdc_rep.t
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Kdc_rep.Ast.t
  end

  (** AS and TGS Exchanges.  TGS-REP.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.3> The Ticket-Granting Service (TGS) Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.4.2> Section KRB_KDC_REP Definition.
  *)
  module Tgs_rep : sig
    type t = Kdc_rep.t
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Kdc_rep.Ast.t
  end

  (** AS and TGS Exchanges.  LastReq.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.1> Section The Authentication Service Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.4.2> Section KRB_KDC_REP Definition.
  *)
  module Last_req : sig
    module Datum : sig
      type t =
        { lr_type : Krb_int32.t
        ; lr_value : Kerberos_time.t
        }
      include Asn1_intf.S with
            type t := t
        and type Ast.t = Krb_int32.Ast.t * Kerberos_time.Ast.t
    end

    type t = Datum.t list
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Datum.Ast.t list
  end

  (** AS and TGS Exchanges.  EncKDCRepPart.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.1> Section The Authentication Service Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.4.2> Section KRB_KDC_REP Definition.
  *)
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

  (** AS and TGS Exchanges.  EncAsRepPart.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.1> Section The Authentication Service Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.4.2> Section KRB_KDC_REP Definition.
  *)
  module Enc_as_rep_part : sig
    type t = Enc_kdc_rep_part.t
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Enc_kdc_rep_part.Ast.t
  end

  (** AS and TGS Exchanges.  EncTgsRepPart.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.1> Section The Authentication Service Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.4.2> Section KRB_KDC_REP Definition.
  *)
  module Enc_tgs_rep_part : sig
    type t = Enc_kdc_rep_part.t
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Enc_kdc_rep_part.Ast.t
  end

  (** Client/Server (CS) Message Specifications. APOptions.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.2> Section The Client/Server Authentication Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.5.1> Section KRB_AP_REQ Definition.
  *)
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

  (** Client/Server (CS) Message Specifications. Authenticator.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.2> Section The Client/Server Authentication Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.5.1> Section KRB_AP_REQ Definition.
  *)
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

  (** Client/Server (CS) Message Specifications. AP-REQ
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.2> Section The Client/Server Authentication Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.5.1> Section KRB_AP_REQ Definition.
  *)
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

  (** Client/Server (CS) Message Specifications. AP-REP
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.2> Section The Client/Server Authentication Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.5.2> Section KRB_AP_REP Definition.
  *)
  module Ap_rep : sig
    type t =
      { enc_part : Encrypted_data.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Z.t * Z.t * Encrypted_data.Ast.t
  end

  (** Client/Server (CS) Message Specifications. EncAPRepPart.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.2> Section The Client/Server Authentication Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.5.2> Section KRB_AP_REP Definition.
  *)
  module Enc_ap_rep_part : sig

      (**
        {b References}
        {ul
          {- IETF. {{:https://tools.ietf.org/html/} RFC prefix link.}}
        }
       *)
    type t =
      { ctime : Kerberos_time.t
      ; cusec : Microseconds.t
      ; subkey : Encryption_key.t option (** IETF rfc4120#section-3.2.6 Using the Encryption Key. *)
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

  (** KRB_SAFE Message Specification.  KRB-SAFE-BODY.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.4> The KRB_SAFE Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.6.1> Section KRB_SAFE Definition.
  *)
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

  (** KRB_SAFE Message Specification.  KRB-SAFE.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.4> The KRB_SAFE Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.6.1> Section KRB_SAFE Definition.
  *)
  module Krb_safe : sig
    type t =
      { safe_body : Krb_safe_body.t
      ; cksum : Checksum.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Z.t * Z.t * Krb_safe_body.Ast.t * Checksum.Ast.t
  end

  (** KRB_PRIV Message Specification.  KRB-PRIV.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.5> The KRB_PRIV Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.7.1> Section KRB_PRIV Definition.
  *)
  module Krb_priv : sig
    type t =
      { enc_part : Encrypted_data.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Z.t * Z.t * Encrypted_data.Ast.t
  end

  (** KRB_PRIV Message Specification.  EncKrbPrivPart.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.5> The KRB_PRIV Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.7.1> Section KRB_PRIV Definition.
  *)
  module Enc_krb_priv_part : sig
    type t = Krb_safe_body.t
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Krb_safe_body.Ast.t
  end

  (** KRB_CRED Message Specification.  KRB-CRED.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.6> The KRB_CRED Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.8.1> KRB_CRED Definition.
  *)
  module Krb_cred : sig
    type t =
      { tickets : Ticket.t list
      ; enc_part : Encrypted_data.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Z.t * Z.t * Ticket.Ast.t list * Encrypted_data.Ast.t
  end

  (** KRB_CRED Message Specification.  KrbCredInfo.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.6> The KRB_CRED Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.8.1> KRB_CRED Definition.
  *)
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

  (** KRB_CRED Message Specification.  EncKrbCredPart.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-3.6> The KRB_CRED Exchange.
      @see <https://tools.ietf.org/html/rfc4120#section-5.8.1> KRB_CRED Definition.
  *)
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

  (** Error Message Specification.  KRB-ERROR.
    
      @see <https://tools.ietf.org/html/rfc4120> RFC
      @see <https://tools.ietf.org/html/rfc4120#section-5.5.3> Error Message Reply.
      @see <https://tools.ietf.org/html/rfc4120#section-5.9.1> KRB_ERROR Definition.
  *)
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

  (** TCP Extensions.
      @see <https://tools.ietf.org/html/rfc5021> RFC
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml> IANA Kerberos parameters
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-3> Kerberos TCP Extensions, Last updated 2017-03-02
  *)
  module Tcp_extension : sig
    module M : sig

      (**
        {b References}
        {ul
          {- IETF. {{:https://tools.ietf.org/html/} RFC prefix link.}}
        }
       *)
      type t =
      | Krb5_over_TLS (** IETF rfc6251 *)
      | Reserved_30 (** IETF rfc5021 *)

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

      (**
        {b References}
        {ul
          {- IETF. {{:https://tools.ietf.org/html/} RFC prefix link.}}
        }
       *)
      type t =
      | Reserved_0 (** IETF rfc6113 *)
      | FX_FAST_ARMOR_AP_REQUEST (** IETF rfc6113 *)

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

      (**
        {b References}
        {ul
          {- IETF. {{:https://tools.ietf.org/html/} RFC prefix link.}}
        }
       *)
      type t =
      | Reserved_0 (** IETF rfc6784 *)
      | UDP (** IETF rfc6784 *)
      | TCP (** IETF rfc6784 *)
      | TLS (** IETF rfc6784 *)

      val alist : (t * int * string) list
    end

    include Asn1_intf.S with
          type t = M.t
      and type Ast.t = Krb_int32.Of_alist(M).Ast.t
  end

  (** FAST Options.
      @see <https://tools.ietf.org/html/rfc6113> RFC
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml> IANA Kerberos parameters
      @see <https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-6> FAST Options, Last updated 2017-03-02
  *)
  module Fast_options : sig
    module Flags : sig

      (**
        {b References}
        {ul
          {- IETF. {{:https://tools.ietf.org/html/} RFC prefix link.}}
        }
       *)
      type t =
      | Reserved_0 (** IETF rfc6113 *)
      | Hide_client_names (** IETF rfc6113 *)
      | Kdc_follow_referrals (** IETF rfc6113 *)

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

  (** Utility msg.  External principal identifier.
      @see <https://tools.ietf.org/html/rfc4556> RFC
      @see <https://tools.ietf.org/html/rfc4556#section-3.2.1> Section Generation of Client Request
  *)
  module External_principal_identifier : sig
    type t =
      { subject_name : Octet_string.t option
      ; issuer_and_serial_number : Octet_string.t option
      ; subject_key_identifier : Octet_string.t option
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Cstruct.t option * Cstruct.t option * Cstruct.t option
  end

  (** Utility msg.  PKINIT Pre-Authentication Client Request.
      @see <https://tools.ietf.org/html/rfc4556> RFC
      @see <https://tools.ietf.org/html/rfc4556#section-3.2.1> Section Generation of Client Request
  *)
  module Pa_pk_as_req : sig
    type t =
      { signed_auth_pack : Octet_string.t
      ; trusted_certifiers : External_principal_identifier.t list
      ; kdc_pk_id : Octet_string.t option
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t =
              Octet_string.Ast.t
            * External_principal_identifier.Ast.t list option
            * Octet_string.Ast.t option
  end

  (** Msg component.  PKINIT Pk authenticator.
      @see <https://tools.ietf.org/html/rfc4556> RFC
      @see <https://tools.ietf.org/html/rfc4556#section-3.2.1> Section Generation of Client Request
  *)
  module Pk_authenticator : sig
    type t =
      { cusec : Microseconds.t
      ; ctime : Kerberos_time.t
      ; nonce : Uint32.t
      ; pa_checksum : Octet_string.t option
      }
    
    include Asn1_intf.S with
          type t := t
      and type Ast.t =
              Microseconds.Ast.t
            * Kerberos_time.Ast.t
            * Uint32.Ast.t
            * Octet_string.Ast.t option
  end

  (** Msg component.  Krb5 Principal Name.
      @see <https://tools.ietf.org/html/rfc4556> RFC
      @see <https://tools.ietf.org/html/rfc4556#section-3.2.2> Section Receipt of Client Request
  *)
  module Krb5_principal_name : sig
    type t =
      { realm : Realm.t
      ; principal_name : Principal_name.t
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Realm.Ast.t * Principal_name.Ast.t
  end

  (** Msg component.  Krb5 Principal Name.
      @see <https://tools.ietf.org/html/rfc4556> RFC
      @see <https://tools.ietf.org/html/rfc4556#section-3.2.2> Section Receipt of Client Request
  *)
  module Dh_rep_info : sig
    type t =
      { dh_signed_data : Octet_string.t
      ; server_dh_nonce : Octet_string.t option
      }
    include Asn1_intf.S with
          type t := t
      and type Ast.t = Octet_string.Ast.t * Octet_string.Ast.t option
  end

  module Types : sig
    val all  : (string * (module Asn1_intf.S)) list
    val some : (string * (module Asn1_intf.S)) list
    val bad  : (string * (module Asn1_intf.S)) list
  end
end

(** The abstract type of a certificate, with
    {{!Encoding.Pem.Certificate}encoding and decoding to PEM}. *)
type t

(** [t_of_sexp sexp] is [certificate], the unmarshalled [sexp]. *)
val t_of_sexp : Sexplib.Sexp.t -> t

(** [sexp_of_t certificate] is [sexp], the marshalled [certificate]. *)
val sexp_of_t : t -> Sexplib.Sexp.t

(** {1 Basic operations on a certificate} *)

(** The polymorphic variant of public key types. *)
type key_type = [ `RSA | `EC of Asn.OID.t ]

(** [supports_keytype certificate key_type] is [result], whether public key of the [certificate] matches the given [key_type]. *)
val supports_keytype : t -> key_type -> bool

(** The polymorphic variant of public keys, with
    {{:http://tools.ietf.org/html/rfc5208}PKCS 8}
    {{!Encoding.Pem.Public_key}encoding and decoding to PEM}. *)
type public_key = [ `RSA of Nocrypto.Rsa.pub | `EC_pub of Asn.OID.t ]

(** [key_id public_key] is [result], the 160-bit [`SHA1] hash of the BIT
    STRING subjectPublicKey (excluding tag, length, and number of
    unused bits) for publicKeyInfo of [public_key].

    {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.2}RFC 5280, 4.2.1.2, variant (1)} *)
val key_id: public_key -> Cstruct.t

(** [key_fingerprint ?hash public_key] is [result], the hash (by
    default SHA256) of the DER encoded public key (equivalent to
    `openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER |
    openssl dgst -HASH`).  *)
val key_fingerprint : ?hash:Nocrypto.Hash.hash -> public_key -> Cstruct.t

(** The polymorphic variant of private keys, with
    {{:http://tools.ietf.org/html/rfc5208}PKCS 8}
    {{!Encoding.Pem.Private_key}encoding and decoding to PEM}. *)
type private_key = [ `RSA of Nocrypto.Rsa.priv ]

(** [public_key certificate] is [pubkey], the public key of the
    [certificate]. *)
val public_key : t -> public_key

(** [hostnames certficate] are [hostnames], the list of hostnames this
    [certificate] is valid for.  Currently, these are the DNS names of
    the {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.6}Subject
    Alternative Name} extension, if present, or otherwise the
    singleton list containing the common name. *)
val hostnames : t -> string list

(** The polymorphic variant for hostname validation. *)
type host = [ `Strict of string | `Wildcard of string ]

(** [supports_hostname certificate host] is [result], whether the
    [certificate] contains the given [host], using
    {!hostnames}. *)
val supports_hostname : t -> host -> bool

(** [common_name_to_string certificate] is [common_name], the common
    name of the subject of the [certificate]. *)
val common_name_to_string : t -> string

(** The polymorphic variant of a distinguished name component, as
    defined in X.500. *)
type component = [
  | `CN           of string
  | `Serialnumber of string
  | `C            of string
  | `L            of string
  | `SP           of string
  | `O            of string
  | `OU           of string
  | `T            of string
  | `DNQ          of string
  | `Mail         of string
  | `DC           of string

  | `Given_name   of string
  | `Surname      of string
  | `Initials     of string
  | `Pseudonym    of string
  | `Generation   of string

  | `Other        of Asn.OID.t * string
]

(** A distinguished name is a list of {!component}. *)
type distinguished_name = component list

(** [distinguished_name_to_string dn] is [string], the string
    representation of the {{!distinguished_name}dn}. *)
val distinguished_name_to_string : distinguished_name -> string

(** [fingerprint hash cert] is [digest],
    the digest of [cert] using the specified [hash] algorithm *)
val fingerprint : Nocrypto.Hash.hash -> t -> Cstruct.t

(** [subject certificate] is [dn], the subject as
    {{!distinguished_name}dn} of the [certificate]. *)
val subject : t -> distinguished_name

(** [issuer certificate] is [dn], the issuer as
    {{!distinguished_name}dn} of the [certificate]. *)
val issuer : t -> distinguished_name

(** [serial certificate] is [sn], the serial number of the
    [certificate]. *)
val serial : t -> Z.t

(** [validity certificate] is [from, until], the validity of the certificate. *)
val validity : t -> Ptime.t * Ptime.t

(** X.509v3 extensions *)
module Extension : sig

  (** {1 X.509v3 extension} *)

  (** The polymorphic variant of
  {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.3}key
  usages}. *)
  type key_usage = [
    | `Digital_signature
    | `Content_commitment
    | `Key_encipherment
    | `Data_encipherment
    | `Key_agreement
    | `Key_cert_sign
    | `CRL_sign
    | `Encipher_only
    | `Decipher_only
  ]

  (** [supports_usage ~not_present certificate key_usage] is [result],
      whether the [certificate] supports the given [key_usage]
      (defaults to [~not_present] if the certificate does not contain
      a keyUsage extension). *)
  val supports_usage : ?not_present:bool -> t -> key_usage -> bool

  (** The polymorphic variant of
  {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.12}extended key
  usages}. *)
  type extended_key_usage = [
    | `Any
    | `Server_auth
    | `Client_auth
    | `Code_signing
    | `Email_protection
    | `Ipsec_end
    | `Ipsec_tunnel
    | `Ipsec_user
    | `Time_stamping
    | `Ocsp_signing
    | `Other of Asn.OID.t
  ]

  (** [supports_extended_usage ~not_present certificate
      extended_key_usage] is [result], whether the [certificate]
      supports the given [extended_key_usage] (defaults to
      [~not_present] if the certificate does not contain an
      extendedKeyUsage extension. *)
  val supports_extended_usage : ?not_present:bool -> t -> extended_key_usage -> bool

  (** A list of [general_name]s is the value of both
      {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.6}subjectAltName}
      and
      {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.7}IssuerAltName}
      extension. *)
  type general_name = [
    | `Other         of (Asn.OID.t * string)
    | `Rfc_822       of string
    | `DNS           of string
    | `X400_address  of unit
    | `Directory     of distinguished_name
    | `EDI_party     of (string option * string)
    | `URI           of string
    | `IP            of Cstruct.t
    | `Registered_id of Asn.OID.t
  ]

  (** The authority key identifier, as present in the
  {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.1}Authority Key
  Identifier} extension. *)
  type authority_key_id = Cstruct.t option * general_name list * Z.t option

  (** The private key usage period, as defined in
  {{:https://tools.ietf.org/html/rfc3280#section-4.2.1.4}RFC 3280}. *)
  type priv_key_usage_period = [
    | `Interval   of Ptime.t * Ptime.t
    | `Not_after  of Ptime.t
    | `Not_before of Ptime.t
  ]

  (** Name constraints, as defined in
  {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.10}RFC
  5280}. *)
  type name_constraint = (general_name * int * int option) list

  (** Certificate policies, the
  {{:https://tools.ietf.org/html/rfc5280#section-4.2.1.4}policy
  extension}. *)
  type policy = [ `Any | `Something of Asn.OID.t ]

  (** The polymorphic variant of
  {{:https://tools.ietf.org/html/rfc5280#section-4.2}X509v3
  extensions}. *)
  type t = [
    | `Unsupported       of Asn.OID.t * Cstruct.t
    | `Subject_alt_name  of general_name list
    | `Authority_key_id  of authority_key_id
    | `Subject_key_id    of Cstruct.t
    | `Issuer_alt_name   of general_name list
    | `Key_usage         of key_usage list
    | `Ext_key_usage     of extended_key_usage list
    | `Basic_constraints of (bool * int option)
    | `Priv_key_period   of priv_key_usage_period
    | `Name_constraints  of name_constraint * name_constraint
    | `Policies          of policy list
  ]
end

(** Certificate Authority operations *)
module CA : sig

  (** {1 Signing} *)

  (** The abstract type of a (self-signed)
  {{:https://tools.ietf.org/html/rfc2986#page-7}PKCS 10 certification
  request}, with {{!Encoding.Pem.Certificate_signing_request}encoding
  and decoding to PEM}. *)
  type signing_request

  (** The polymorphic variant of certificate request extensions, as
      defined in {{:http://tools.ietf.org/html/rfc2985}PKCS 9
      (RFC 2985)}. *)
  type request_extensions = [
    | `Password of string
    | `Name of string
    | `Extensions of (bool * Extension.t) list
  ]

  (** The raw request info of a
      {{:https://tools.ietf.org/html/rfc2986#section-4}PKCS 10
      certification request info}. *)
  type request_info = {
    subject    : distinguished_name ;
    public_key : public_key ;
    extensions : request_extensions list ;
  }

  (** [info signing_request] is {!request_info}, the information
      inside the {!signing_request}. *)
  val info : signing_request -> request_info

  (** [request subject ~digest ~extensions private] creates
      [signing_request], a certification request using the given
      [subject], [digest] (defaults to [`SHA256]) and list of
      [extensions]. *)
  val request : distinguished_name -> ?digest:Nocrypto.Hash.hash -> ?extensions:request_extensions list -> private_key -> signing_request

  (** [sign signing_request ~digest ~valid_from ~valid_until ~serial
      ~extensions private issuer] creates [certificate], a signed
      certificate.  Public key and subject are taken from the
      [signing_request], the [extensions] are added to the X.509
      certificate.  The [private] key is used to sign the certificate,
      the [issuer] is recorded in the certificate.  The digest
      defaults to [`SHA256].  The [serial] defaults to a random value
      between 1 and 2^64.  Certificate version is always 3.  Please
      note that the extensions in the [signing_request] are ignored,
      you can pass them using:

{[match
  try Some (List.find (function `Extensions _ -> true | _ -> false) (info csr).extensions)
  with Not_found -> None
with
 | Some (`Extensions x) -> x
 | None -> []
]}. *)
  val sign : signing_request -> valid_from:Ptime.t -> valid_until:Ptime.t -> ?digest:Nocrypto.Hash.hash -> ?serial:Z.t -> ?extensions:(bool * Extension.t) list -> private_key -> distinguished_name -> t
end

(** X.509 Certificate Chain Validation. *)
module Validation : sig
  (** A chain of pairwise signed X.509 certificates is sent to the endpoint,
      which use these to authenticate the other endpoint.  Usually a set of
      trust anchors is configured on the endpoint, and the chain needs to be
      rooted in one of the trust anchors.  In reality, chains may be incomplete
      or reversed, and there can be multiple paths from the leaf certificate to
      a trust anchor.

      RFC 5280 specifies a {{:https://tools.ietf.org/html/rfc5280#section-6}path
      validation} algorithm for authenticating chains, but this does not handle
      multiple possible paths.  {{:https://tools.ietf.org/html/rfc4158}RFC 4158}
      describes possible path building strategies.

      This module provides path building, chain of trust verification, trust
      anchor (certificate authority) validation, and validation via a
      fingerprint list (for a trust on first use implementation).
  *)


  (** {2 Certificate Authorities} *)

  (** The polymorphic variant of possible certificate authorities failures. *)
  type ca_error = [
    | `CAIssuerSubjectMismatch of t
    | `CAInvalidVersion of t
    | `CAInvalidSelfSignature of t
    | `CACertificateExpired of t * float option
    | `CAInvalidExtensions of t
  ]

  (** [ca_error_of_sexp sexp] is [ca_error], the unmarshalled [sexp]. *)
  val ca_error_of_sexp : Sexplib.Sexp.t -> ca_error

  (** [sexp_of_ca_error ca_error] is [sexp], the marshalled [ca_error]. *)
  val sexp_of_ca_error : ca_error -> Sexplib.Sexp.t

  (** [ca_error_to_string validation_error] is [string], the string representation of the [ca_error]. *)
  val ca_error_to_string : ca_error -> string

  (** [valid_ca ~time certificate] is [result], which is `Ok if the given
      certificate is self-signed, it is valid at [time], its extensions are not
      present (if X.509 version 1 certificate), or are appropriate for a CA
      (BasicConstraints is present and true, KeyUsage extension contains
      keyCertSign). *)
  val valid_ca : ?time:Ptime.t -> t -> [ `Ok | `Error of ca_error ]

  (** [valid_cas ~time certificates] is [valid_certificates], only
      those certificates which pass the {!valid_ca} check. *)
  val valid_cas : ?time:Ptime.t -> t list -> t list

  (** {2 Chain of trust verification} *)

  (** The polymorphic variant of a leaf certificate validation error. *)
  type leaf_validation_error = [
    | `LeafCertificateExpired of t * float option
    | `LeafInvalidName of t * host option
    | `LeafInvalidVersion of t
    | `LeafInvalidExtensions of t
  ]

  (** The polymorphic variant of a chain validation error. *)
  type chain_validation_error = [
    | `IntermediateInvalidExtensions of t
    | `IntermediateCertificateExpired of t * float option
    | `IntermediateInvalidVersion of t

    | `ChainIssuerSubjectMismatch of t * t
    | `ChainAuthorityKeyIdSubjectKeyIdMismatch of t * t
    | `ChainInvalidSignature of t * t
    | `ChainInvalidPathlen of t * int

    | `EmptyCertificateChain
    | `NoTrustAnchor of t
  ]

  (** [build_paths server rest] is [paths], which are all possible certificate
      paths starting with [server].  These chains (C1..Cn) fulfill the predicate
      that each certificate Cn is issued by the next one in the chain (C(n+1)):
      the issuer of Cn matches the subject of C(n+1).  This is as described in
      {{:https://tools.ietf.org/html/rfc4158}RFC 4158}. *)
  val build_paths : t -> t list -> t list list

  (** The polymorphic variant of a chain validation error: either the leaf
      certificate is problematic, or the chain itself. *)
  type chain_error = [
    | `Leaf of leaf_validation_error
    | `Chain of chain_validation_error
  ]

  (** [chain_error_of_sexp sexp] is [chain_error], the unmarshalled [sexp]. *)
  val chain_error_of_sexp : Sexplib.Sexp.t -> chain_error

  (** [sexp_of_chain_error chain_error] is [sexp], the marshalled [chain_error]. *)
  val sexp_of_chain_error : chain_error -> Sexplib.Sexp.t

  (** [chain_error_to_string validation_error] is [string], the string representation of the [chain_error]. *)
  val chain_error_to_string : chain_error -> string

  (** [verify_chain ~host ~time ~anchors chain] is [result], either [Ok] and the
      trust anchor used to verify the chain, or [Fail] and the chain error.  RFC
      5280 describes the implemented
      {{:https://tools.ietf.org/html/rfc5280#section-6.1}path validation}
      algorithm: The validity period of the given certificates is checked
      against the [time].  The X509v3 extensions of the [chain] are checked,
      then a chain of trust from [anchors] to the server certificate is
      validated.  The path length constraints are checked.  The server
      certificate is checked to contain the given [host], using {!hostnames}.
      The returned certificate is the root of the chain, a member of the given
      list of [anchors]. *)
  val verify_chain : ?host:host -> ?time:Ptime.t -> anchors:(t list) -> t list -> [ `Ok of t | `Fail of chain_error ]

  (** The polymorphic variant of a fingerprint validation error. *)
  type fingerprint_validation_error = [
    | `ServerNameNotPresent of t * string
    | `NameNotInList of t
    | `InvalidFingerprint of t * Cstruct.t * Cstruct.t
  ]

  (** The polymorphic variant of validation errors. *)
  type validation_error = [
    | `EmptyCertificateChain
    | `InvalidChain
    | `Leaf of leaf_validation_error
    | `Fingerprint of fingerprint_validation_error
  ]

  (** [validation_error_of_sexp sexp] is [validation_error], the unmarshalled [sexp]. *)
  val validation_error_of_sexp : Sexplib.Sexp.t -> validation_error

  (** [sexp_of_validation_error validation_error] is [sexp], the marshalled [validation_error]. *)
  val sexp_of_validation_error : validation_error -> Sexplib.Sexp.t

  (** [validation_error_to_string validation_error] is [string], the string representation of the [validation_error]. *)
  val validation_error_to_string : validation_error -> string

  (** The result of a validation: either success (optionally returning the used trust anchor), or failure *)
  type result = [
    | `Ok of (t list * t) option
    | `Fail of validation_error
  ]

  (** [verify_chain_of_trust ~host ~time ~anchors certificates] is [result].
      First, all possible paths are constructed using the {!build_paths}
      function, the first certificate of the chain is verified to be a valid
      leaf certificate (no BasicConstraints extension) and contains the given
      [host] (using {!hostnames}); if some path is valid, using {!verify_chain},
      the result will be [Ok] and contain the actual certificate chain and the
      trust anchor. *)
  val verify_chain_of_trust :
    ?host:host -> ?time:Ptime.t -> anchors:(t list) -> t list -> result

  (** {2 Fingerprint verification} *)

  (** [trust_key_fingerprint ~time ~hash ~fingerprints certificates]
      is [result], the first element of [certificates] is verified
      against the given [fingerprints] map (hostname to public key
      fingerprint) using {!key_fingerprint}.  The certificate has to
      be valid in the given [time].  If a [host] is provided, the
      certificate is checked for this name.  The [`Wildcard hostname]
      of the fingerprint list must match the name in the certificate,
      using {!hostnames}. *)
  val trust_key_fingerprint :
    ?host:host -> ?time:Ptime.t -> hash:Nocrypto.Hash.hash ->
    fingerprints:(string * Cstruct.t) list -> t list -> result

  (** [trust_cert_fingerprint ~time ~hash ~fingerprints certificates]
      is [result], the first element of [certificates] is verified to
      match the given [fingerprints] map (hostname to fingerprint)
      using {!fingerprint}.  The certificate has to be valid in the
      given [time].  If a [host] is provided, the certificate is
      checked for this name.  The [`Wildcard hostname] of the
      fingerprint list must match the name in the certificate, using
      {!hostnames}.

      @deprecated "Pin public keys, not certificates (use {!trust_key_fingerprint} instead)." *)
  val trust_cert_fingerprint :
    ?host:host -> ?time:Ptime.t -> hash:Nocrypto.Hash.hash ->
    fingerprints:(string * Cstruct.t) list -> t list -> result
end

(** Authenticators of certificate chains *)
module Authenticator : sig

  (** {1 Authenticators} *)

  (** An authenticator [a] is a function type which takes a hostname
      and a certificate stack to an authentication decision
      {!Validation.result}. *)
  type a = ?host:host -> t list -> Validation.result

  (** [chain_of_trust ?time trust_anchors] is [authenticator], which
      uses the given [time] and list of [trust_anchors] to verify the
      certificate chain. This is an implementation of the algorithm
      described in
      {{:https://tools.ietf.org/html/rfc5280#section-6.1}RFC 5280},
      using {!Validation.verify_chain_of_trust}.  The given trust
      anchors are not checked to be valid trust anchors any further
      (you have to do this manually with {!Validation.valid_ca} or
      {!Validation.valid_cas})!  *)
  val chain_of_trust : ?time:Ptime.t -> t list -> a

  (** [server_key_fingerprint ~time hash fingerprints] is an
      [authenticator] which uses the given [time] and list of
      [fingerprints] to verify that the fingerprint of the first
      element of the certificate chain matches the given fingerprint,
      using {!Validation.trust_key_fingerprint}. *)
  val server_key_fingerprint : ?time:Ptime.t -> hash:Nocrypto.Hash.hash ->
    fingerprints:(string * Cstruct.t) list -> a

  (** [server_cert_fingerprint ~time hash fingerprints] is an
      [authenticator] which uses the given [time] and list of
      [fingerprints] to verify the first element of the certificate
      chain, using {!Validation.trust_cert_fingerprint}.

      @deprecated "Pin public keys, not certificates (use {!server_key_fingerprint} instead)." *)
  val server_cert_fingerprint : ?time:Ptime.t -> hash:Nocrypto.Hash.hash ->
    fingerprints:(string * Cstruct.t) list -> a

  (** [null] is [authenticator], which always returns [`Ok]. (Useful
      for testing purposes only.) *)
  val null : a

  (** [a_of_sexp sexp] is [authenticator], the unmarshalled
  [sexp].  Note: only {!null} is supported. *)
  val a_of_sexp : Sexplib.Sexp.t -> a

  (** [sexp_of_a authenticator] is [sexp], the marshalled
  [authenticator].  Note: always emits {!null}. *)
  val sexp_of_a : a -> Sexplib.Sexp.t
end

(** Encodings *)
module Encoding : sig

  (** {1 ASN.1 Encoding} *)

  (** [parse cstruct] is [certificate option], the ASN.1 decoded
      [certificate] or [None]. *)
  val parse : Cstruct.t -> t option

  (** [cs_of_cert certificate] is [cstruct], the ASN.1 encoded
      representation of the [certificate]. *)
  val cs_of_cert  : t -> Cstruct.t

  (** [cs_of_distinguished_name dn] is [cstruct], the ASN.1 encoded
      representation of the distinguished name [dn]. *)
  val cs_of_distinguished_name : distinguished_name -> Cstruct.t

  (** [parse_signing_request cstruct] is [signing_request option],
      the ASN.1 decoded [cstruct] or [None]. *)
  val parse_signing_request : Cstruct.t -> CA.signing_request option

  (** [cs_of_signing_request sr] is [cstruct], the ASN.1 encoded
      representation of the [sr]. *)
  val cs_of_signing_request  : CA.signing_request -> Cstruct.t

  (** [pkcs1_digest_info_of_cstruct data] is [hash, signature option],
      the hash and raw signature. *)
  val pkcs1_digest_info_of_cstruct : Cstruct.t ->
    (Nocrypto.Hash.hash * Cstruct.t) option

  (** [pkcs1_digest_info_to_cstruct (hash, signature)] is [data], the
      encoded hash and signature. *)
  val pkcs1_digest_info_to_cstruct : (Nocrypto.Hash.hash * Cstruct.t) -> Cstruct.t

  (** [rsa_public_to_cstruct pk] is [buffer], the ASN.1 encoding of the
      given public key. *)
  val rsa_public_to_cstruct : Nocrypto.Rsa.pub -> Cstruct.t

  (** [rsa_public_of_cstruct buffer] is [pubkey], the public key of
      the ASN.1 encoded buffer. *)
  val rsa_public_of_cstruct : Cstruct.t -> Nocrypto.Rsa.pub option

  (** Parser and unparser of PEM files *)
  module Pem : sig

    (** {2 PEM encoding} *)

    (** [parse pem] is [(name * data) list], in which the [pem] is
        parsed into its components, each surrounded by [BEGIN name] and
        [END name]. The actual [data] is base64 decoded. *)
    val parse : Cstruct.t -> (string * Cstruct.t) list

    (** Decoding and encoding of
       {{:https://tools.ietf.org/html/rfc5280#section-3.1}X509
       certificates} in PEM format *)
    module Certificate : sig

      (** {3 PEM encoded certificates} *)

      (** [of_pem_cstruct pem] is [t list], where all certificates of
          the [pem] are extracted *)
      val of_pem_cstruct  : Cstruct.t -> t list

      (** [of_pem_cstruct1 pem] is [t], where the single certificate
          of the [pem] is extracted *)
      val of_pem_cstruct1 : Cstruct.t -> t

      (** [to_pem_cstruct certificates] is [pem], the pem encoded
          certificates. *)
      val to_pem_cstruct : t list -> Cstruct.t

      (** [to_pem_cstruct1 certificate] is [pem], the pem encoded
          certificate. *)
      val to_pem_cstruct1 : t -> Cstruct.t
    end

    (** Decoding and encoding of
        {{:https://tools.ietf.org/html/rfc2986}PKCS 10 certification
        requests} in PEM format *)
    module Certificate_signing_request : sig

      (** {3 PEM encoded certificate signing requests} *)

      type t = CA.signing_request

      (** [of_pem_cstruct pem] is [t list], where all signing requests
          of the [pem] are extracted *)
      val of_pem_cstruct  : Cstruct.t -> t list

      (** [of_pem_cstruct1 pem] is [t], where the single signing
          request of the [pem] is extracted *)
      val of_pem_cstruct1 : Cstruct.t -> t

      (** [to_pem_cstruct signing_requests] is [pem], the pem encoded
          signing requests. *)
      val to_pem_cstruct : t list -> Cstruct.t

      (** [to_pem_cstruct1 signing_request] is [pem], the pem encoded
          signing_request. *)
      val to_pem_cstruct1 : t -> Cstruct.t
    end

    (** Decoding and encoding of public keys in PEM format as defined
        in {{:http://tools.ietf.org/html/rfc5208}PKCS 8} *)
    module Public_key : sig

      (** {3 PEM encoded RSA keys} *)

      (** [of_pem_cstruct pem] is [t list], where all public keys of
          [pem] are extracted *)
      val of_pem_cstruct  : Cstruct.t -> public_key list

      (** [of_pem_cstruct1 pem] is [t], where the public key of [pem]
          is extracted *)
      val of_pem_cstruct1 : Cstruct.t -> public_key

      (** [to_pem_cstruct public_keys] is [pem], the pem encoded
          public keys. *)
      val to_pem_cstruct : public_key list -> Cstruct.t

      (** [to_pem_cstruct1 public_key] is [pem], the pem encoded
          public key. *)
      val to_pem_cstruct1 : public_key -> Cstruct.t
    end

    (** Decoding and encoding of unencrypted private RSA keys in PEM
        format as defined in
        {{:http://tools.ietf.org/html/rfc5208}PKCS 8} *)
    module Private_key : sig

      (** {3 PEM encoded RSA keys} *)

      (** [of_pem_cstruct pem] is [t list], where all private keys of
          [pem] are extracted *)
      val of_pem_cstruct  : Cstruct.t -> private_key list

      (** [of_pem_cstruct1 pem] is [t], where the private key of [pem]
          is extracted *)
      val of_pem_cstruct1 : Cstruct.t -> private_key

      (** [to_pem_cstruct private_keys] is [pem], the pem encoded
          private keys. *)
      val to_pem_cstruct : private_key list -> Cstruct.t

      (** [to_pem_cstruct1 private_key] is [pem], the pem encoded
          private key. *)
      val to_pem_cstruct1 : private_key -> Cstruct.t
    end
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
