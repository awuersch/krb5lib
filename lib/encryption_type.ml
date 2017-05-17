open Sexplib.Std

(** {{https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-1} Kerberos Encryption Type Numbers, Last updated 2017-03-02} *)
type ty =
  | Reserved_0                   (* rfc6448 *)
  | Des_cbc_crc                  (* rfc3961 *)
  | Des_cbc_md4                  (* rfc3961 *)
  | Des_cbc_md5                  (* rfc3961 *)
  | Reserved_1                   (* rfc3961 *)
  | Des3_cbc_md5                 (* ?? *)
  | Reserved_2                   (* rfc3961 *)
  | Des3_cbc_sha1                (* ?? *)
  | DsaWithSHA1_CmsOID           (* rfc4556 *)
  | Md5WithRSAEncryption_CmsOID  (* rfc4556 *)
  | Sha1WithRSAEncryption_CmsOID (* rfc4556 *)
  | Rc2CBC_EnvOID                (* rfc4556 *)
  | RsaEncryption_EnvOID         (* rfc4556 [from PKCS #1 v1.5] *)
  | RsaES_OAEP_ENV_OID           (* rfc4556 [from PKCS #1 v2.0] *)
  | Des_ede3_cbc_Env_OID         (* rfc4556 *)
  | Des3_cbc_sha1_kd             (* rfc3961 *)
  | Aes128_cts_hmac_sha1_96      (* rfc3962 *)
  | Aes256_cts_hmac_sha1_96      (* rfc3962 *)
  | Aes128_cts_hmac_sha256_128   (* rfc8009 *)
  | Aes256_cts_hmac_sha384_192   (* rfc8009 *)
  | Rc4_hmac                     (* rfc4757 *)
  | Rc4_hmac_exp                 (* rfc4757 *)
  | Camellia128_cts_cmac         (* rfc6803 *)
  | Camellia256_cts_cmac         (* rfc6803 *)
  | Subkey_keymaterial           (* [(opaque; PacketCable)] *)
  [@@deriving sexp]

module M = struct
  type t = ty

  let alist =
    [ Reserved_0                  , 0, "Reserved_0"
    ; Des_cbc_crc                 , 1, "Des_cbc_crc"
    ; Des_cbc_md4                 , 2, "Des_cbc_md4"
    ; Des_cbc_md5                 , 3, "Des_cbc_md5"
    ; Reserved_1                  , 4, "Reserved_1"
    ; Des3_cbc_md5                , 5, "Des3_cbc_md5"
    ; Reserved_2                  , 6, "Reserved_2"
    ; Des3_cbc_sha1               , 7, "Des3_cbc_sha1"
    ; DsaWithSHA1_CmsOID          , 9, "DsaWithSHA1_CmsOID"
    ; Md5WithRSAEncryption_CmsOID , 10, "Md5WithRSAEncryption_CmsOID"
    ; Sha1WithRSAEncryption_CmsOID, 11, "Sha1WithRSAEncryption_CmsOID"
    ; Rc2CBC_EnvOID               , 12, "Rc2CBC_EnvOID"
    ; RsaEncryption_EnvOID        , 13, "RsaEncryption_EnvOID"
    ; RsaES_OAEP_ENV_OID          , 14, "RsaES_OAEP_ENV_OID"
    ; Des_ede3_cbc_Env_OID        , 15, "Des_ede3_cbc_Env_OID"
    ; Des3_cbc_sha1_kd            , 16, "Des3_cbc_sha1_kd"
    ; Aes128_cts_hmac_sha1_96     , 17, "Aes128_cts_hmac_sha1_96"
    ; Aes256_cts_hmac_sha1_96     , 18, "Aes256_cts_hmac_sha1_96"
    ; Aes128_cts_hmac_sha256_128  , 19, "Aes128_cts_hmac_sha256_128"
    ; Aes256_cts_hmac_sha384_192  , 20, "Aes256_cts_hmac_sha384_192"
    ; Rc4_hmac                    , 23, "Rc4_hmac"
    ; Rc4_hmac_exp                , 24, "Rc4_hmac_exp"
    ; Camellia128_cts_cmac        , 25, "Camellia128_cts_cmac"
    ; Camellia256_cts_cmac        , 26, "Camellia256_cts_cmac"
    ; Subkey_keymaterial          , 65, "Subkey_keymaterial"
    ]
end

module Asn1 = Krb_int32.Of_alist(M)
include Asn1

(* I bet this list will grow longer one day. *)
let is_weak t =
  match t with
  | Des_cbc_crc
  | Des_cbc_md4
  | Des_cbc_md5
  | Rc4_hmac_exp -> true
  | _ -> false

(* Certain steps of the krb5 protocol are different depending on how old the encryption type is.
   Thus we expose a function to test whether an encryption type is considered new or old. *)
let is_newer_than_rfc_4120 t =
  match t with
  | Reserved_0
  | Des3_cbc_md5
  | Des3_cbc_sha1
  | DsaWithSHA1_CmsOID
  | Md5WithRSAEncryption_CmsOID
  | Sha1WithRSAEncryption_CmsOID
  | Rc2CBC_EnvOID
  | RsaEncryption_EnvOID
  | RsaES_OAEP_ENV_OID
  | Des_ede3_cbc_Env_OID
  | Aes128_cts_hmac_sha256_128
  | Aes256_cts_hmac_sha384_192
  | Rc4_hmac
  | Rc4_hmac_exp
  | Camellia128_cts_cmac
  | Camellia256_cts_cmac
  | Subkey_keymaterial -> true
  | _ -> false
