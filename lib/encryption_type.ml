(*
Feb 2005

des-cbc-crc                        1             6.2.3
      des-cbc-md4                        2             6.2.2
      des-cbc-md5                        3             6.2.1
      [reserved]                         4
      des3-cbc-md5                       5
      [reserved]                         6
      des3-cbc-sha1                      7
      dsaWithSHA1-CmsOID                 9           (pkinit)
      md5WithRSAEncryption-CmsOID       10           (pkinit)
      sha1WithRSAEncryption-CmsOID      11           (pkinit)
      rc2CBC-EnvOID                     12           (pkinit)
      rsaEncryption-EnvOID              13   (pkinit from PKCS#1 v1.5)
      rsaES-OAEP-ENV-OID                14   (pkinit from PKCS#1 v2.0)
      des-ede3-cbc-Env-OID              15           (pkinit)
      des3-cbc-sha1-kd                  16              6.3
      aes128-cts-hmac-sha1-96           17          [KRB5-AES]
      aes256-cts-hmac-sha1-96           18          [KRB5-AES]
      rc4-hmac                          23          (Microsoft)
      rc4-hmac-exp                      24          (Microsoft)
      subkey-keymaterial                65     (opaque; PacketCable)
*)

(* CR bbohrer: I have no idea what any of these are, I should double-check
   with RFC 3961 *)
open Sexplib.Std

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
  [@@deriving sexp]


module Alist = struct
  type nonrec t = ty

  let alist =
    [ Des_cbc_crc                       , 1
    ; Des_cbc_md4                       , 2
    ; Des_cbc_md5                       , 3
    ; Reserved4                         , 4
    ; Des3_cbc_md5                      , 5
    ; Reserved6                         , 6
    ; Des3_cbc_sha1                     , 7
    ; Dsa_with_sha1_cms_oid             , 9
    ; Md5WithRSAEncryption_cmsOID       , 10
    ; Sha1WithRSAEncryption_cmsOID      , 11
    ; Rc2CBC_EnvOID                     , 12
    ; Rsa_encryption_envOID             , 13
    ; Rsa_es_oaepSenvOID                , 14
    ; Des_ede3_cbc_envOID               , 15
    ; Des3_cbc_sha1_kd                  , 16
    ; Aes128_cts_hmac_sha1_96           , 17
    ; Aes256_cts_hmac_sha1_96           , 18
    ; Rc4_hmac                          , 23
    ; Rc4_hmac_exp                      , 24
    ; Subkey_keymaterial                , 65
    ]
end

(* I bet this list will grow longer one day. *)
let is_weak t =
  match t with
  | Des_cbc_crc
  | Des_cbc_md4
  | Des_cbc_md5
  | Rc4_hmac_exp -> true
  | _ -> false

(* CR bbohrer: This may not be 100% correct. I just followed the following rule from RFC 4120:
 RC4, DES, 3DES and anything in RFC 1510 are not "newer"
*)
(* Certain steps of the krb5 protocol are different depending on how old the encryption type is.
   Thus we expose a function to test whether an encryption type is considered new or old. *)
let is_newer_than_rfc_4120 t =
  match t with
  | Des_cbc_crc
  | Des_cbc_md4
  | Des_cbc_md5
  | Des3_cbc_md5
  | Des3_cbc_sha1
  | Rc4_hmac
  | Rc4_hmac_exp
  | Des_ede3_cbc_envOID
  | Des3_cbc_sha1_kd -> false
  | Reserved4
  | Reserved6
  | Dsa_with_sha1_cms_oid
  | Md5WithRSAEncryption_cmsOID
  | Sha1WithRSAEncryption_cmsOID
  | Rc2CBC_EnvOID
  | Rsa_encryption_envOID
  | Rsa_es_oaepSenvOID
  | Aes128_cts_hmac_sha1_96
  | Aes256_cts_hmac_sha1_96
  | Subkey_keymaterial -> true

module Asn1 = Krb_int32.Of_alist(Alist)
include Asn1
