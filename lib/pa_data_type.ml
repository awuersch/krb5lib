module M = struct
  type t =
  | PA_TGS_REQ                 (* [RFC4120] *)
  | PA_ENC_TIMESTAMP           (* [RFC4120] *)
  | PA_PW_SALT                 (* [RFC4120] *)
  | Reserved_0                 (* [RFC6113] *)
  | PA_ENC_UNIX_TIME           (* (deprecated) [RFC4120] *)
  | PA_SANDIA_SECUREID         (* [RFC4120] *)
  | PA_SESAME                  (* [RFC4120] *)
  | PA_OSF_DCE                 (* [RFC4120] *)
  | PA_CYBERSAFE_SECUREID      (* [RFC4120] *)
  | PA_AFS3_SALT               (* [RFC4120][RFC3961] *)
  | PA_ETYPE_INFO              (* [RFC4120] *)
  | PA_SAM_CHALLENGE           (* [draft-ietf-cat-kerberos-passwords-04] *)
  | PA_SAM_RESPONSE            (* [draft-ietf-cat-kerberos-passwords-04] *)
  | PA_PK_AS_REQ_OLD           (* [draft-ietf-cat-kerberos-pk-init-09] *)
  | PA_PK_AS_REP_OLD           (* [draft-ietf-cat-kerberos-pk-init-09] *)
  | PA_PK_AS_REQ               (* [RFC4556] *)
  | PA_PK_AS_REP               (* [RFC4556] *)
  | PA_PK_OCSP_RESPONSE        (* [RFC4557] *)
  | PA_ETYPE_INFO2             (* [RFC4120] *)
  | PA_USE_SPECIFIED_KVNO      (* [RFC4120] *)
  | PA_SVR_REFERRAL_INFO       (* [RFC6806] *)
  | PA_SAM_REDIRECT            (* [draft-ietf-krb-wg-kerberos-sam-03] *)
  | PA_GET_FROM_TYPED_DATA     (* [(embedded in typed data)][RFC4120] *)
  | TD_PADATA                  (* [(embeds padata)][RFC4120] *)
  | PA_SAM_ETYPE_INFO          (* [(sam/otp)][draft-ietf-krb-wg-kerberos-sam-03] *)
  | PA_ALT_PRINC               (* [draft-ietf-krb-wg-hw-auth-04] *)
  | PA_SERVER_REFERRAL         (* [draft-ietf-krb-wg-kerberos-referrals-11] *)
  | PA_SAM_CHALLENGE2          (* [draft-ietf-krb-wg-kerberos-sam-03] *)
  | PA_SAM_RESPONSE2           (* [draft-ietf-krb-wg-kerberos-sam-03] *)
  | PA_EXTRA_TGT               (* [Reserved extra TGT][RFC6113] *)
  | TD_PKINIT_CMS_CERTIFICATES (* [RFC4556] *)
  | TD_KRB_PRINCIPAL           (* [PrincipalName][RFC6113] *)
  | TD_KRB_REALM               (* [Realm][RFC6113] *)
  | TD_TRUSTED_CERTIFIERS      (* [RFC4556] *)
  | TD_CERTIFICATE_INDEX       (* [RFC4556] *)
  | TD_APP_DEFINED_ERROR       (* [Application specific][RFC6113] *)
  | TD_REQ_NONCE               (* [INTEGER][RFC6113] *)
  | TD_REQ_SEQ                 (* [INTEGER][RFC6113] *)
  | TD_DH_PARAMETERS           (* [RFC4556] *)
  | TD_CMS_DIGEST_ALGORITHMS   (* [draft-ietf-krb-wg-pkinit-alg-agility] *)
  | TD_CERT_DIGEST_ALGORITHMS  (* [draft-ietf-krb-wg-pkinit-alg-agility] *)
  | PA_PAC_REQUEST             (* [MSKILE][http://msdn2.microsoft.com/en_us/library/cc206927.aspx] *)
  | PA_FOR_USER                (* [MSKILE][http://msdn2.microsoft.com/en_us/library/cc206927.aspx] *)
  | PA_FOR_X509_USER           (* [MSKILE][http://msdn2.microsoft.com/en_us/library/cc206927.aspx] *)
  | PA_FOR_CHECK_DUPS          (* [MSKILE][http://msdn2.microsoft.com/en_us/library/cc206927.aspx] *)
  | PA_AS_CHECKSUM             (* [MSKILE][http://msdn2.microsoft.com/en_us/library/cc206927.aspx] *)
  | PA_FX_COOKIE               (* [RFC6113] *)
  | PA_AUTHENTICATION_SET      (* [RFC6113] *)
  | PA_AUTH_SET_SELECTED       (* [RFC6113] *)
  | PA_FX_FAST                 (* [RFC6113] *)
  | PA_FX_ERROR                (* [RFC6113] *)
  | PA_ENCRYPTED_CHALLENGE     (* [RFC6113] *)
  | PA_OTP_CHALLENGE           (* [RFC6560] *)
  | PA_OTP_REQUEST             (* [RFC6560] *)
  | PA_OTP_CONFIRM             (* (obsoleted) [RFC6560] *)
  | PA_OTP_PIN_CHANGE          (* [RFC6560] *)
  | PA_EPAK_AS_REQ             (* [(sshock@gmail.com)][RFC6113] *)
  | PA_EPAK_AS_REP             (* [(sshock@gmail.com)][RFC6113] *)
  | PA_PKINIT_KX               (* [RFC8062] *)
  | PA_PKU2U_NAME              (* [draft-zhu-pku2u] *)
  | PA_REQ_ENC_PA_REP          (* [RFC6806] *)
  | PA_AS_FRESHNESS            (* [RFC8070] *)
  | PA_SUPPORTED_ETYPES        (* [MSKILE][http://msdn2.microsoft.com/en_us/library/cc206927.aspx] *)
  | PA_EXTENDED_ERROR          (* [MSKILE][http://msdn2.microsoft.com/en_us/library/cc206927.aspx] *)
  [@@deriving sexp]

  let alist =
    [ PA_TGS_REQ, 1, "PA_TGS_REQ"
    ; PA_ENC_TIMESTAMP, 2, "PA_ENC_TIMESTAMP"
    ; PA_PW_SALT, 3, "PA_PW_SALT"
    ; Reserved_0, 4, "Reserved_0"
    ; PA_ENC_UNIX_TIME, 5, "PA_ENC_UNIX_TIME"
    ; PA_SANDIA_SECUREID, 6, "PA_SANDIA_SECUREID"
    ; PA_SESAME, 7, "PA_SESAME"
    ; PA_OSF_DCE, 8, "PA_OSF_DCE"
    ; PA_CYBERSAFE_SECUREID, 9, "PA_CYBERSAFE_SECUREID"
    ; PA_AFS3_SALT, 10, "PA_AFS3_SALT"
    ; PA_ETYPE_INFO, 11, "PA_ETYPE_INFO"
    ; PA_SAM_CHALLENGE, 12, "PA_SAM_CHALLENGE"
    ; PA_SAM_RESPONSE, 13, "PA_SAM_RESPONSE"
    ; PA_PK_AS_REQ_OLD, 14, "PA_PK_AS_REQ_OLD"
    ; PA_PK_AS_REP_OLD, 15, "PA_PK_AS_REP_OLD"
    ; PA_PK_AS_REQ, 16, "PA_PK_AS_REQ"
    ; PA_PK_AS_REP, 17, "PA_PK_AS_REP"
    ; PA_PK_OCSP_RESPONSE, 18, "PA_PK_OCSP_RESPONSE"
    ; PA_ETYPE_INFO2, 19, "PA_ETYPE_INFO2"
    ; PA_USE_SPECIFIED_KVNO, 20, "PA_USE_SPECIFIED_KVNO"
    ; PA_SVR_REFERRAL_INFO, 20, "PA_SVR_REFERRAL_INFO"
    ; PA_SAM_REDIRECT, 21, "PA_SAM_REDIRECT"
    ; PA_GET_FROM_TYPED_DATA, 22, "PA_GET_FROM_TYPED_DATA"
    ; TD_PADATA, 22, "TD_PADATA"
    ; PA_SAM_ETYPE_INFO, 23, "PA_SAM_ETYPE_INFO"
    ; PA_ALT_PRINC, 24, "PA_ALT_PRINC"
    ; PA_SERVER_REFERRAL, 25, "PA_SERVER_REFERRAL"
    ; PA_SAM_CHALLENGE2, 30, "PA_SAM_CHALLENGE2"
    ; PA_SAM_RESPONSE2, 31, "PA_SAM_RESPONSE2"
    ; PA_EXTRA_TGT, 41, "PA_EXTRA_TGT"
    ; TD_PKINIT_CMS_CERTIFICATES, 101, "TD_PKINIT_CMS_CERTIFICATES"
    ; TD_KRB_PRINCIPAL, 102, "TD_KRB_PRINCIPAL"
    ; TD_KRB_REALM, 103, "TD_KRB_REALM"
    ; TD_TRUSTED_CERTIFIERS, 104, "TD_TRUSTED_CERTIFIERS"
    ; TD_CERTIFICATE_INDEX, 105, "TD_CERTIFICATE_INDEX"
    ; TD_APP_DEFINED_ERROR, 106, "TD_APP_DEFINED_ERROR"
    ; TD_REQ_NONCE, 107, "TD_REQ_NONCE"
    ; TD_REQ_SEQ, 108, "TD_REQ_SEQ"
    ; TD_DH_PARAMETERS, 109, "TD_DH_PARAMETERS"
    ; TD_CMS_DIGEST_ALGORITHMS, 111, "TD_CMS_DIGEST_ALGORITHMS"
    ; TD_CERT_DIGEST_ALGORITHMS, 112, "TD_CERT_DIGEST_ALGORITHMS"
    ; PA_PAC_REQUEST, 128, "PA_PAC_REQUEST"
    ; PA_FOR_USER, 129, "PA_FOR_USER"
    ; PA_FOR_X509_USER, 130, "PA_FOR_X509_USER"
    ; PA_FOR_CHECK_DUPS, 131, "PA_FOR_CHECK_DUPS"
    ; PA_AS_CHECKSUM, 132, "PA_AS_CHECKSUM"
    ; PA_FX_COOKIE, 133, "PA_FX_COOKIE"
    ; PA_AUTHENTICATION_SET, 134, "PA_AUTHENTICATION_SET"
    ; PA_AUTH_SET_SELECTED, 135, "PA_AUTH_SET_SELECTED"
    ; PA_FX_FAST, 136, "PA_FX_FAST"
    ; PA_FX_ERROR, 137, "PA_FX_ERROR"
    ; PA_ENCRYPTED_CHALLENGE, 138, "PA_ENCRYPTED_CHALLENGE"
    ; PA_OTP_CHALLENGE, 141, "PA_OTP_CHALLENGE"
    ; PA_OTP_REQUEST, 142, "PA_OTP_REQUEST"
    ; PA_OTP_CONFIRM, 143, "PA_OTP_CONFIRM"
    ; PA_OTP_PIN_CHANGE, 144, "PA_OTP_PIN_CHANGE"
    ; PA_EPAK_AS_REQ, 145, "PA_EPAK_AS_REQ"
    ; PA_EPAK_AS_REP, 146, "PA_EPAK_AS_REP"
    ; PA_PKINIT_KX, 147, "PA_PKINIT_KX"
    ; PA_PKU2U_NAME, 148, "PA_PKU2U_NAME"
    ; PA_REQ_ENC_PA_REP, 149, "PA_REQ_ENC_PA_REP"
    ; PA_AS_FRESHNESS, 150, "PA_AS_FRESHNESS"
    ; PA_SUPPORTED_ETYPES, 165, "PA_SUPPORTED_ETYPES"
    ; PA_EXTENDED_ERROR, 166, "PA_EXTENDED_ERROR"
    ]
end

module Asn1 = Krb_int32.Of_alist (M)
include Asn1
