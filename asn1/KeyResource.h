/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "KeyContainer"
 * 	found in "KeyContainer.asn1"
 * 	`asn1c -fwide-types -pdu=all`
 */

#ifndef	_KeyResource_H_
#define	_KeyResource_H_


#include <asn_application.h>

/* Including external dependencies */
#include "CipherKeyResource.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Validity;

/* KeyResource */
typedef struct KeyResource {
	CipherKeyResource_t	*counter	/* OPTIONAL */;
	struct Validity	*time	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} KeyResource_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_KeyResource;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "AsymmetricKeyResource.h"

#endif	/* _KeyResource_H_ */
#include <asn_internal.h>
