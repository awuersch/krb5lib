(** Kerberos V5 GSS-API status codes per rfc4121
    @see <https://tools.ietf.org/html/4121#section-4.2.6.1>
    @see <https://tools.ietf.org/html/4121#section-5.1>
*)
type code =
| GSS_KRB5_S_G_BAD_SERVICE_NAME
| GSS_KRB5_S_G_BAD_STRING_UID
| GSS_KRB5_S_G_NOUSER
| GSS_KRB5_S_G_VALIDATE_FAILED
| GSS_KRB5_S_G_BUFFER_ALLOC
| GSS_KRB5_S_G_BAD_MSG_CTX
| GSS_KRB5_S_G_WRONG_SIZE
| GSS_KRB5_S_G_BAD_USAGE
| GSS_KRB5_S_G_UNKNOWN_OOP
| GSS_KRB5_S_KG_CCACHE_NOMATCH
| GSS_KRB5_S_KG_KEYTAB_NOMATCH
| GSS_KRB5_S_KG_TGT_MISSING
| GSS_KRB5_S_KG_NO_SUBKEY
| GSS_KRB5_S_KG_CONTEXT_ESTABLISHED
| GSS_KRB5_S_KG_BAD_SIGN_TYPE
| GSS_KRB5_S_KG_BAD_LENGTH
| GSS_KRB5_S_KG_CTX_INCOMPLETE

let is_kerberos_specific = function
| GSS_KRB5_S_G_BAD_SERVICE_NAME
| GSS_KRB5_S_G_BAD_STRING_UID
| GSS_KRB5_S_G_NOUSER
| GSS_KRB5_S_G_VALIDATE_FAILED
| GSS_KRB5_S_G_BUFFER_ALLOC
| GSS_KRB5_S_G_BAD_MSG_CTX
| GSS_KRB5_S_G_WRONG_SIZE
| GSS_KRB5_S_G_BAD_USAGE
| GSS_KRB5_S_G_UNKNOWN_OOP -> false
| GSS_KRB5_S_KG_CCACHE_NOMATCH
| GSS_KRB5_S_KG_KEYTAB_NOMATCH
| GSS_KRB5_S_KG_TGT_MISSING
| GSS_KRB5_S_KG_NO_SUBKEY
| GSS_KRB5_S_KG_CONTEXT_ESTABLISHED
| GSS_KRB5_S_KG_BAD_SIGN_TYPE
| GSS_KRB5_S_KG_BAD_LENGTH
| GSS_KRB5_S_KG_CTX_INCOMPLETE -> true

let code_to_string = function
| GSS_KRB5_S_G_BAD_SERVICE_NAME -> "No @ in SERVICE-NAME name string"
| GSS_KRB5_S_G_BAD_STRING_UID   -> "STRING-UID-NAME contains nondigits"
| GSS_KRB5_S_G_NOUSER           -> "UID does not resolve to username"
| GSS_KRB5_S_G_VALIDATE_FAILED  -> "Validation error"
| GSS_KRB5_S_G_BUFFER_ALLOC     -> "Couldn't allocate gss_buffer_t data"
| GSS_KRB5_S_G_BAD_MSG_CTX      -> "Message context invalid"
| GSS_KRB5_S_G_WRONG_SIZE       -> "Buffer is the wrong size"
| GSS_KRB5_S_G_BAD_USAGE        -> "Credential usage type is unknown"
| GSS_KRB5_S_G_UNKNOWN_OOP      -> "Unknown quality of protection specified"
| GSS_KRB5_S_KG_CCACHE_NOMATCH  -> "Client principal in credentials does not match specified name"
| GSS_KRB5_S_KG_KEYTAB_NOMATCH  -> "No key available for specified service principal"
| GSS_KRB5_S_KG_TGT_MISSING     -> "No Kerberos ticket-granting ticket available"
| GSS_KRB5_S_KG_NO_SUBKEY       -> "Authenticator has no subkey"
| GSS_KRB5_S_KG_CONTEXT_ESTABLISHED -> "Context is already fully established"
| GSS_KRB5_S_KG_BAD_SIGN_TYPE   -> "Unknown signature type in token"
| GSS_KRB5_S_KG_BAD_LENGTH      -> "Invalid field length in token"
| GSS_KRB5_S_KG_CTX_INCOMPLETE  -> "Attempt to use incomplete security context"

type key_usage_code =
| KG_USAGE_ACCEPTOR_SEAL
| KG_USAGE_ACCEPTOR_SIGN
| KG_USAGE_INITIATOR_SEAL
| KG_USAGE_INITIATOR_SIGN

let key_usage_value = function
| KG_USAGE_ACCEPTOR_SEAL  -> 22
| KG_USAGE_ACCEPTOR_SIGN  -> 23
| KG_USAGE_INITIATOR_SEAL -> 24
| KG_USAGE_INITIATOR_SIGN -> 25
