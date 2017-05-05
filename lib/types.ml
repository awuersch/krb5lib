let all =
[ "Address_type", (module Address_type : Asn1_intf.S)
; "As_req", (module As_req : Asn1_intf.S)
; "Authorization_data", (module Authorization_data : Asn1_intf.S)
; "Encryption_type", (module Encryption_type : Asn1_intf.S)
; "Address_type", (module Address_type : Asn1_intf.S)
; "Encrypted_data", (module Encrypted_data : Asn1_intf.S)
; "Encryption_key", (module Encryption_key : Asn1_intf.S)
; "Enc_ticket_part", (module Enc_ticket_part : Asn1_intf.S)
; "Host_addresses", (module Host_addresses : Asn1_intf.S)
; "Host_address", (module Host_address : Asn1_intf.S)
; "Kdc_options", (module Kdc_options : Asn1_intf.S)
; "Kdc_req_body", (module Kdc_req_body : Asn1_intf.S)
; "Kdc_req", (module Kdc_req : Asn1_intf.S)
; "Kerberos_time", (module Kerberos_time : Asn1_intf.S)
; "Kerberos_string", (module Kerberos_string : Asn1_intf.S)
; "Krb_int32", (module Krb_int32 : Asn1_intf.S)
; "Name_type", (module Name_type : Asn1_intf.S)
; "Octet_string", (module Octet_string : Asn1_intf.S)
; "Pa_data", (module Pa_data : Asn1_intf.S)
; "Principal_name", (module Principal_name : Asn1_intf.S)
; "Realm", (module Realm : Asn1_intf.S)
; "Ticket_flags", (module Ticket_flags : Asn1_intf.S)
; "Ticket", (module Ticket : Asn1_intf.S)
; "Transited_encoding", (module Transited_encoding : Asn1_intf.S)
; "Uint32", (module Uint32 : Asn1_intf.S)
]

let some =
[ "Krb_int32", (module Krb_int32 : Asn1_intf.S)
; "Uint32", (module Uint32 : Asn1_intf.S)
; "Octet_string", (module Octet_string : Asn1_intf.S)
; "Kerberos_string", (module Kerberos_string : Asn1_intf.S)
; "Kerberos_time", (module Kerberos_time : Asn1_intf.S)
; "Realm", (module Realm : Asn1_intf.S)
; "Name_type", (module Name_type : Asn1_intf.S)
]

let bad =
[ "Encryption_key", (module Encryption_key : Asn1_intf.S)
; "Name_type", (module Name_type : Asn1_intf.S)
]
