open Sexplib.Std

(** {{https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-2} Kerberos Checksum Type Numbers, Last updated 2017-03-02} *)

module M = struct
  type t =
    | Reserved_0             (* rfc3961, section 6.1.3 *)
    | CRC32                  (* rfc3961, section 6.1.3 *)
    | Rsa_md4                (* rfc3961, section 6.1.2 *)
    | Rsa_md4_des            (* rfc3961, section 6.2.5 *)
    | Des_mac                (* rfc3961, section 6.2.7 *)
    | Des_mac_k              (* rfc3961, section 6.2.8 *)
    | Rsa_md4_des_k          (* rfc3961, section 6.2.6 *)
    | Rsa_md5                (* rfc3961, section 6.1.1 *)
    | Rsa_md5_des            (* rfc3961, section 6.2.4 *)
    | Rsa_md5_des3           (* ?? *)
    | Sha1_unkeyed_0         (* ?? *)
    | Hmac_sha1_des3_kd      (* rfc3961, section 6.3 *)
    | Hmac_sha1_des3         (* ?? *)
    | Sha1_unkeyed_1         (* ?? *)
    | Hmac_sha1_96_aes128    (* rfc3962 *)
    | Hmac_sha1_96_aes256    (* rfc3962 *)
    | Cmac_camellia128       (* rfc6803 *)
    | Cmac_camellia256       (* rfc6803 *)
    | Hmac_sha256_128_aes128 (* rfc8009 *)
    | Hmac_sha256_192_aes256 (* rfc8009 *)
    | Reserved_1             (* rfc1964 *)
    [@@deriving sexp]

  let alist =
    [ Reserved_0            , 0, "Reserved_0"
    ; CRC32                 , 1, "CRC32"
    ; Rsa_md4               , 2, "Rsa_md4"
    ; Rsa_md4_des           , 3, "Rsa_md4_des"
    ; Des_mac               , 4, "Des_mac"
    ; Des_mac_k             , 5, "Des_mac_k"
    ; Rsa_md4_des_k         , 6, "Rsa_md4_des_k"
    ; Rsa_md5               , 7, "Rsa_md5"
    ; Rsa_md5_des           , 8, "Rsa_md5_des"
    ; Rsa_md5_des3          , 9, "Rsa_md5_des3"
    ; Sha1_unkeyed_0        , 10, "Sha1_unkeyed_0"
    ; Hmac_sha1_des3_kd     , 12, "Hmac_sha1_des3_kd"
    ; Hmac_sha1_des3        , 13, "Hmac_sha1_des3"
    ; Sha1_unkeyed_1        , 14, "Sha1_unkeyed_1"
    ; Hmac_sha1_96_aes128   , 15, "Hmac_sha1_96_aes128"
    ; Hmac_sha1_96_aes256   , 16, "Hmac_sha1_96_aes256"
    ; Cmac_camellia128      , 17, "Cmac_camellia128"
    ; Cmac_camellia256      , 18, "Cmac_camellia256"
    ; Hmac_sha256_128_aes128, 19, "Hmac_sha256_128_aes128"
    ; Hmac_sha256_192_aes256, 20, "Hmac_sha256_192_aes256"
    ; Reserved_1            , 32771, "Reserved_1"
    ]
end

module Asn1 = Krb_int32.Of_alist(M)
include Asn1
