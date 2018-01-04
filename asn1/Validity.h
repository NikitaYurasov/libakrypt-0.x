/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "KeyContainer"
 * 	found in "KeyContainer.asn1"
 * 	`asn1c -fwide-types -pdu=all`
 */

#ifndef	_Validity_H_
#define	_Validity_H_


#include <asn_application.h>

/* Including external dependencies */
#include <GeneralizedTime.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Validity */
typedef struct Validity {
	GeneralizedTime_t	 notBefore;
	GeneralizedTime_t	 notAfter;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Validity_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Validity;

#ifdef __cplusplus
}
#endif

#endif	/* _Validity_H_ */
#include <asn_internal.h>
