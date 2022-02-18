/* SPDX-License-Identifier: LGPL-2.1 */
#ifndef _COMMON_SMB2PDU_H
#define _COMMON_SMB2PDU_H

/*
 * Note that, due to trying to use names similar to the protocol specifications,
 * there are many mixed case field names in the structures below.  Although
 * this does not match typical Linux kernel style, it is necessary to be
 * able to match against the protocol specfication.
 *
 * SMB2 commands
 * Some commands have minimal (wct=0,bcc=0), or uninteresting, responses
 * (ie no useful data other than the SMB error code itself) and are marked such.
 * Knowing this helps avoid response buffer allocations and copy in some cases.
 */

/* List of commands in host endian */
#define SMB2_NEGOTIATE_HE	0x0000
#define SMB2_SESSION_SETUP_HE	0x0001
#define SMB2_LOGOFF_HE		0x0002 /* trivial request/resp */
#define SMB2_TREE_CONNECT_HE	0x0003
#define SMB2_TREE_DISCONNECT_HE	0x0004 /* trivial req/resp */
#define SMB2_CREATE_HE		0x0005
#define SMB2_CLOSE_HE		0x0006
#define SMB2_FLUSH_HE		0x0007 /* trivial resp */
#define SMB2_READ_HE		0x0008
#define SMB2_WRITE_HE		0x0009
#define SMB2_LOCK_HE		0x000A
#define SMB2_IOCTL_HE		0x000B
#define SMB2_CANCEL_HE		0x000C
#define SMB2_ECHO_HE		0x000D
#define SMB2_QUERY_DIRECTORY_HE	0x000E
#define SMB2_CHANGE_NOTIFY_HE	0x000F
#define SMB2_QUERY_INFO_HE	0x0010
#define SMB2_SET_INFO_HE	0x0011
#define SMB2_OPLOCK_BREAK_HE	0x0012

/* The same list in little endian */
#define SMB2_NEGOTIATE		cpu_to_le16(SMB2_NEGOTIATE_HE)
#define SMB2_SESSION_SETUP	cpu_to_le16(SMB2_SESSION_SETUP_HE)
#define SMB2_LOGOFF		cpu_to_le16(SMB2_LOGOFF_HE)
#define SMB2_TREE_CONNECT	cpu_to_le16(SMB2_TREE_CONNECT_HE)
#define SMB2_TREE_DISCONNECT	cpu_to_le16(SMB2_TREE_DISCONNECT_HE)
#define SMB2_CREATE		cpu_to_le16(SMB2_CREATE_HE)
#define SMB2_CLOSE		cpu_to_le16(SMB2_CLOSE_HE)
#define SMB2_FLUSH		cpu_to_le16(SMB2_FLUSH_HE)
#define SMB2_READ		cpu_to_le16(SMB2_READ_HE)
#define SMB2_WRITE		cpu_to_le16(SMB2_WRITE_HE)
#define SMB2_LOCK		cpu_to_le16(SMB2_LOCK_HE)
#define SMB2_IOCTL		cpu_to_le16(SMB2_IOCTL_HE)
#define SMB2_CANCEL		cpu_to_le16(SMB2_CANCEL_HE)
#define SMB2_ECHO		cpu_to_le16(SMB2_ECHO_HE)
#define SMB2_QUERY_DIRECTORY	cpu_to_le16(SMB2_QUERY_DIRECTORY_HE)
#define SMB2_CHANGE_NOTIFY	cpu_to_le16(SMB2_CHANGE_NOTIFY_HE)
#define SMB2_QUERY_INFO		cpu_to_le16(SMB2_QUERY_INFO_HE)
#define SMB2_SET_INFO		cpu_to_le16(SMB2_SET_INFO_HE)
#define SMB2_OPLOCK_BREAK	cpu_to_le16(SMB2_OPLOCK_BREAK_HE)

#define SMB2_INTERNAL_CMD	cpu_to_le16(0xFFFF)

#define NUMBER_OF_SMB2_COMMANDS	0x0013

/*
 * SMB2 Header Definition
 *
 * "MBZ" :  Must be Zero
 * "BB"  :  BugBug, Something to check/review/analyze later
 * "PDU" :  "Protocol Data Unit" (ie a network "frame")
 *
 */

#define __SMB2_HEADER_STRUCTURE_SIZE	64
#define SMB2_HEADER_STRUCTURE_SIZE				\
	cpu_to_le16(__SMB2_HEADER_STRUCTURE_SIZE)

#define SMB2_PROTO_NUMBER cpu_to_le32(0x424d53fe)
#define SMB2_TRANSFORM_PROTO_NUM cpu_to_le32(0x424d53fd)
#define SMB2_COMPRESSION_TRANSFORM_ID cpu_to_le32(0x424d53fc)

/*
 *	SMB2 flag definitions
 */
#define SMB2_FLAGS_SERVER_TO_REDIR	cpu_to_le32(0x00000001)
#define SMB2_FLAGS_ASYNC_COMMAND	cpu_to_le32(0x00000002)
#define SMB2_FLAGS_RELATED_OPERATIONS	cpu_to_le32(0x00000004)
#define SMB2_FLAGS_SIGNED		cpu_to_le32(0x00000008)
#define SMB2_FLAGS_PRIORITY_MASK	cpu_to_le32(0x00000070) /* SMB3.1.1 */
#define SMB2_FLAGS_DFS_OPERATIONS	cpu_to_le32(0x10000000)
#define SMB2_FLAGS_REPLAY_OPERATION	cpu_to_le32(0x20000000) /* SMB3 & up */

/* See MS-SMB2 section 2.2.1 */
struct smb2_hdr {
	__le32 ProtocolId;	/* 0xFE 'S' 'M' 'B' */
	__le16 StructureSize;	/* 64 */
	__le16 CreditCharge;	/* MBZ */
	__le32 Status;		/* Error from server */
	__le16 Command;
	__le16 CreditRequest;	/* CreditResponse */
	__le32 Flags;
	__le32 NextCommand;
	__le64 MessageId;
	union {
		struct {
			__le32 ProcessId;
			__le32  TreeId;
		} __packed SyncId;
		__le64  AsyncId;
	} __packed Id;
	__le64  SessionId;
	__u8   Signature[16];
} __packed;

struct smb2_pdu {
	struct smb2_hdr hdr;
	__le16 StructureSize2; /* size of wct area (varies, request specific) */
} __packed;

#define SMB3_AES_CCM_NONCE 11
#define SMB3_AES_GCM_NONCE 12

/* Transform flags (for 3.0 dialect this flag indicates CCM */
#define TRANSFORM_FLAG_ENCRYPTED	0x0001
struct smb2_transform_hdr {
	__le32 ProtocolId;	/* 0xFD 'S' 'M' 'B' */
	__u8   Signature[16];
	__u8   Nonce[16];
	__le32 OriginalMessageSize;
	__u16  Reserved1;
	__le16 Flags; /* EncryptionAlgorithm for 3.0, enc enabled for 3.1.1 */
	__le64  SessionId;
} __packed;


/* See MS-SMB2 2.2.42 */
struct smb2_compression_transform_hdr_unchained {
	__le32 ProtocolId;	/* 0xFC 'S' 'M' 'B' */
	__le32 OriginalCompressedSegmentSize;
	__le16 CompressionAlgorithm;
	__le16 Flags;
	__le16 Length; /* if chained it is length, else offset */
} __packed;

/* See MS-SMB2 2.2.42.1 */
#define SMB2_COMPRESSION_FLAG_NONE	0x0000
#define SMB2_COMPRESSION_FLAG_CHAINED	0x0001

struct compression_payload_header {
	__le16	CompressionAlgorithm;
	__le16	Flags;
	__le32	Length; /* length of compressed playload including field below if present */
	/* __le32 OriginalPayloadSize; */ /* optional, present when LZNT1, LZ77, LZ77+Huffman */
} __packed;

/* See MS-SMB2 2.2.42.2 */
struct smb2_compression_transform_hdr_chained {
	__le32 ProtocolId;	/* 0xFC 'S' 'M' 'B' */
	__le32 OriginalCompressedSegmentSize;
	/* struct compression_payload_header[] */
} __packed;

/* See MS-SMB2 2.2.42.2.2 */
struct compression_pattern_payload_v1 {
	__le16	Pattern;
	__le16	Reserved1;
	__le16	Reserved2;
	__le32	Repetitions;
} __packed;

/* See MS-SMB2 section 2.2.9.2 */
/* Context Types */
#define SMB2_RESERVED_TREE_CONNECT_CONTEXT_ID 0x0000
#define SMB2_REMOTED_IDENTITY_TREE_CONNECT_CONTEXT_ID cpu_to_le16(0x0001)

struct tree_connect_contexts {
	__le16 ContextType;
	__le16 DataLength;
	__le32 Reserved;
	__u8   Data[];
} __packed;

/* Remoted identity tree connect context structures - see MS-SMB2 2.2.9.2.1 */
struct smb3_blob_data {
	__le16 BlobSize;
	__u8   BlobData[];
} __packed;

/* Valid values for Attr */
#define SE_GROUP_MANDATORY		0x00000001
#define SE_GROUP_ENABLED_BY_DEFAULT	0x00000002
#define SE_GROUP_ENABLED		0x00000004
#define SE_GROUP_OWNER			0x00000008
#define SE_GROUP_USE_FOR_DENY_ONLY	0x00000010
#define SE_GROUP_INTEGRITY		0x00000020
#define SE_GROUP_INTEGRITY_ENABLED	0x00000040
#define SE_GROUP_RESOURCE		0x20000000
#define SE_GROUP_LOGON_ID		0xC0000000

/* struct sid_attr_data is SidData array in BlobData format then le32 Attr */

struct sid_array_data {
	__le16 SidAttrCount;
	/* SidAttrList - array of sid_attr_data structs */
} __packed;

struct luid_attr_data {

} __packed;

/*
 * struct privilege_data is the same as BLOB_DATA - see MS-SMB2 2.2.9.2.1.5
 * but with size of LUID_ATTR_DATA struct and BlobData set to LUID_ATTR DATA
 */

struct privilege_array_data {
	__le16 PrivilegeCount;
	/* array of privilege_data structs */
} __packed;

struct remoted_identity_tcon_context {
	__le16 TicketType; /* must be 0x0001 */
	__le16 TicketSize; /* total size of this struct */
	__le16 User; /* offset to SID_ATTR_DATA struct with user info */
	__le16 UserName; /* offset to null terminated Unicode username string */
	__le16 Domain; /* offset to null terminated Unicode domain name */
	__le16 Groups; /* offset to SID_ARRAY_DATA struct with group info */
	__le16 RestrictedGroups; /* similar to above */
	__le16 Privileges; /* offset to PRIVILEGE_ARRAY_DATA struct */
	__le16 PrimaryGroup; /* offset to SID_ARRAY_DATA struct */
	__le16 Owner; /* offset to BLOB_DATA struct */
	__le16 DefaultDacl; /* offset to BLOB_DATA struct */
	__le16 DeviceGroups; /* offset to SID_ARRAY_DATA struct */
	__le16 UserClaims; /* offset to BLOB_DATA struct */
	__le16 DeviceClaims; /* offset to BLOB_DATA struct */
	__u8   TicketInfo[]; /* variable length buf - remoted identity data */
} __packed;

struct smb2_tree_connect_req_extension {
	__le32 TreeConnectContextOffset;
	__le16 TreeConnectContextCount;
	__u8  Reserved[10];
	__u8  PathName[]; /* variable sized array */
	/* followed by array of TreeConnectContexts */
} __packed;

/* Flags/Reserved for SMB3.1.1 */
#define SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT cpu_to_le16(0x0001)
#define SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER cpu_to_le16(0x0002)
#define SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT cpu_to_le16(0x0004)

struct smb2_tree_connect_req {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 9 */
	__le16 Flags;		/* Flags in SMB3.1.1 */
	__le16 PathOffset;
	__le16 PathLength;
	__u8   Buffer[1];	/* variable length */
} __packed;

/* Possible ShareType values */
#define SMB2_SHARE_TYPE_DISK	0x01
#define SMB2_SHARE_TYPE_PIPE	0x02
#define	SMB2_SHARE_TYPE_PRINT	0x03

/*
 * Possible ShareFlags - exactly one and only one of the first 4 caching flags
 * must be set (any of the remaining, SHI1005, flags may be set individually
 * or in combination.
 */
#define SMB2_SHAREFLAG_MANUAL_CACHING			0x00000000
#define SMB2_SHAREFLAG_AUTO_CACHING			0x00000010
#define SMB2_SHAREFLAG_VDO_CACHING			0x00000020
#define SMB2_SHAREFLAG_NO_CACHING			0x00000030
#define SHI1005_FLAGS_DFS				0x00000001
#define SHI1005_FLAGS_DFS_ROOT				0x00000002
#define SHI1005_FLAGS_RESTRICT_EXCLUSIVE_OPENS		0x00000100
#define SHI1005_FLAGS_FORCE_SHARED_DELETE		0x00000200
#define SHI1005_FLAGS_ALLOW_NAMESPACE_CACHING		0x00000400
#define SHI1005_FLAGS_ACCESS_BASED_DIRECTORY_ENUM	0x00000800
#define SHI1005_FLAGS_FORCE_LEVELII_OPLOCK		0x00001000
#define SHI1005_FLAGS_ENABLE_HASH_V1			0x00002000
#define SHI1005_FLAGS_ENABLE_HASH_V2			0x00004000
#define SHI1005_FLAGS_ENCRYPT_DATA			0x00008000
#define SMB2_SHAREFLAG_IDENTITY_REMOTING		0x00040000 /* 3.1.1 */
#define SMB2_SHAREFLAG_COMPRESS_DATA			0x00100000 /* 3.1.1 */
#define SHI1005_FLAGS_ALL				0x0014FF33

/* Possible share capabilities */
#define SMB2_SHARE_CAP_DFS	cpu_to_le32(0x00000008) /* all dialects */
#define SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY cpu_to_le32(0x00000010) /* 3.0 */
#define SMB2_SHARE_CAP_SCALEOUT	cpu_to_le32(0x00000020) /* 3.0 */
#define SMB2_SHARE_CAP_CLUSTER	cpu_to_le32(0x00000040) /* 3.0 */
#define SMB2_SHARE_CAP_ASYMMETRIC cpu_to_le32(0x00000080) /* 3.02 */
#define SMB2_SHARE_CAP_REDIRECT_TO_OWNER cpu_to_le32(0x00000100) /* 3.1.1 */

struct smb2_tree_connect_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 16 */
	__u8   ShareType;	/* see below */
	__u8   Reserved;
	__le32 ShareFlags;	/* see below */
	__le32 Capabilities;	/* see below */
	__le32 MaximalAccess;
} __packed;

struct smb2_tree_disconnect_req {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 4 */
	__le16 Reserved;
} __packed;

struct smb2_tree_disconnect_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 4 */
	__le16 Reserved;
} __packed;


/*
 * SMB2_NEGOTIATE_PROTOCOL  See MS-SMB2 section 2.2.3
 */
/* SecurityMode flags */
#define	SMB2_NEGOTIATE_SIGNING_ENABLED     0x0001
#define	SMB2_NEGOTIATE_SIGNING_ENABLED_LE  cpu_to_le16(0x0001)
#define SMB2_NEGOTIATE_SIGNING_REQUIRED	   0x0002
#define SMB2_NEGOTIATE_SIGNING_REQUIRED_LE cpu_to_le16(0x0002)
#define SMB2_SEC_MODE_FLAGS_ALL            0x0003

/* Capabilities flags */
#define SMB2_GLOBAL_CAP_DFS		0x00000001
#define SMB2_GLOBAL_CAP_LEASING		0x00000002 /* Resp only New to SMB2.1 */
#define SMB2_GLOBAL_CAP_LARGE_MTU	0X00000004 /* Resp only New to SMB2.1 */
#define SMB2_GLOBAL_CAP_MULTI_CHANNEL	0x00000008 /* New to SMB3 */
#define SMB2_GLOBAL_CAP_PERSISTENT_HANDLES 0x00000010 /* New to SMB3 */
#define SMB2_GLOBAL_CAP_DIRECTORY_LEASING  0x00000020 /* New to SMB3 */
#define SMB2_GLOBAL_CAP_ENCRYPTION	0x00000040 /* New to SMB3 */
/* Internal types */
#define SMB2_NT_FIND			0x00100000
#define SMB2_LARGE_FILES		0x00200000

#define SMB2_CLIENT_GUID_SIZE		16
#define SMB2_CREATE_GUID_SIZE		16

/* Dialects */
#define SMB10_PROT_ID  0x0000 /* local only, not sent on wire w/CIFS negprot */
#define SMB20_PROT_ID  0x0202
#define SMB21_PROT_ID  0x0210
#define SMB2X_PROT_ID  0x02FF
#define SMB30_PROT_ID  0x0300
#define SMB302_PROT_ID 0x0302
#define SMB311_PROT_ID 0x0311
#define BAD_PROT_ID    0xFFFF

#define SMB311_SALT_SIZE			32
/* Hash Algorithm Types */
#define SMB2_PREAUTH_INTEGRITY_SHA512	cpu_to_le16(0x0001)
#define SMB2_PREAUTH_HASH_SIZE 64

/* Negotiate Contexts - ContextTypes. See MS-SMB2 section 2.2.3.1 for details */
#define SMB2_PREAUTH_INTEGRITY_CAPABILITIES	cpu_to_le16(1)
#define SMB2_ENCRYPTION_CAPABILITIES		cpu_to_le16(2)
#define SMB2_COMPRESSION_CAPABILITIES		cpu_to_le16(3)
#define SMB2_NETNAME_NEGOTIATE_CONTEXT_ID	cpu_to_le16(5)
#define SMB2_TRANSPORT_CAPABILITIES		cpu_to_le16(6)
#define SMB2_RDMA_TRANSFORM_CAPABILITIES	cpu_to_le16(7)
#define SMB2_SIGNING_CAPABILITIES		cpu_to_le16(8)
#define SMB2_POSIX_EXTENSIONS_AVAILABLE		cpu_to_le16(0x100)

struct smb2_neg_context {
	__le16	ContextType;
	__le16	DataLength;
	__le32	Reserved;
	/* Followed by array of data. NOTE: some servers require padding to 8 byte boundary */
} __packed;

/*
 * SaltLength that the server send can be zero, so the only three required
 * fields (all __le16) end up six bytes total, so the minimum context data len
 * in the response is six bytes which accounts for
 *
 *      HashAlgorithmCount, SaltLength, and 1 HashAlgorithm.
 */
#define MIN_PREAUTH_CTXT_DATA_LEN 6

struct smb2_preauth_neg_context {
	__le16	ContextType; /* 1 */
	__le16	DataLength;
	__le32	Reserved;
	__le16	HashAlgorithmCount; /* 1 */
	__le16	SaltLength;
	__le16	HashAlgorithms; /* HashAlgorithms[0] since only one defined */
	__u8	Salt[SMB311_SALT_SIZE];
} __packed;

/* Encryption Algorithms Ciphers */
#define SMB2_ENCRYPTION_AES128_CCM	cpu_to_le16(0x0001)
#define SMB2_ENCRYPTION_AES128_GCM	cpu_to_le16(0x0002)
#define SMB2_ENCRYPTION_AES256_CCM      cpu_to_le16(0x0003)
#define SMB2_ENCRYPTION_AES256_GCM      cpu_to_le16(0x0004)

/* Min encrypt context data is one cipher so 2 bytes + 2 byte count field */
#define MIN_ENCRYPT_CTXT_DATA_LEN	4
struct smb2_encryption_neg_context {
	__le16	ContextType; /* 2 */
	__le16	DataLength;
	__le32	Reserved;
	/* CipherCount usally 2, but can be 3 when AES256-GCM enabled */
	__le16	CipherCount; /* AES128-GCM and AES128-CCM by default */
	__le16	Ciphers[];
} __packed;

/* See MS-SMB2 2.2.3.1.3 */
#define SMB3_COMPRESS_NONE	cpu_to_le16(0x0000)
#define SMB3_COMPRESS_LZNT1	cpu_to_le16(0x0001)
#define SMB3_COMPRESS_LZ77	cpu_to_le16(0x0002)
#define SMB3_COMPRESS_LZ77_HUFF	cpu_to_le16(0x0003)
/* Pattern scanning algorithm See MS-SMB2 3.1.4.4.1 */
#define SMB3_COMPRESS_PATTERN	cpu_to_le16(0x0004) /* Pattern_V1 */

/* Compression Flags */
#define SMB2_COMPRESSION_CAPABILITIES_FLAG_NONE		cpu_to_le32(0x00000000)
#define SMB2_COMPRESSION_CAPABILITIES_FLAG_CHAINED	cpu_to_le32(0x00000001)

struct smb2_compression_capabilities_context {
	__le16	ContextType; /* 3 */
	__le16  DataLength;
	__le32	Reserved;
	__le16	CompressionAlgorithmCount;
	__le16	Padding;
	__le32	Flags;
	__le16	CompressionAlgorithms[3];
	__u16	Pad;  /* Some servers require pad to DataLen multiple of 8 */
	/* Check if pad needed */
} __packed;

/*
 * For smb2_netname_negotiate_context_id See MS-SMB2 2.2.3.1.4.
 * Its struct simply contains NetName, an array of Unicode characters
 */
struct smb2_netname_neg_context {
	__le16	ContextType; /* 5 */
	__le16	DataLength;
	__le32	Reserved;
	__le16	NetName[]; /* hostname of target converted to UCS-2 */
} __packed;

/*
 * For smb2_transport_capabilities context see MS-SMB2 2.2.3.1.5
 * and 2.2.4.1.5
 */

/* Flags */
#define SMB2_ACCEPT_TRANSFORM_LEVEL_SECURITY	0x00000001

struct smb2_transport_capabilities_context {
	__le16	ContextType; /* 6 */
	__le16  DataLength;
	__u32	Reserved;
	__le32	Flags;
	__u32	Pad;
} __packed;

/*
 * For rdma transform capabilities context see MS-SMB2 2.2.3.1.6
 * and 2.2.4.1.6
 */

/* RDMA Transform IDs */
#define SMB2_RDMA_TRANSFORM_NONE	0x0000
#define SMB2_RDMA_TRANSFORM_ENCRYPTION	0x0001
#define SMB2_RDMA_TRANSFORM_SIGNING	0x0002

struct smb2_rdma_transform_capabilities_context {
	__le16	ContextType; /* 7 */
	__le16  DataLength;
	__u32	Reserved;
	__le16	TransformCount;
	__u16	Reserved1;
	__u32	Reserved2;
	__le16	RDMATransformIds[];
} __packed;

/*
 * For signing capabilities context see MS-SMB2 2.2.3.1.7
 * and 2.2.4.1.7
 */

/* Signing algorithms */
#define SIGNING_ALG_HMAC_SHA256    0
#define SIGNING_ALG_HMAC_SHA256_LE cpu_to_le16(0)
#define SIGNING_ALG_AES_CMAC       1
#define SIGNING_ALG_AES_CMAC_LE    cpu_to_le16(1)
#define SIGNING_ALG_AES_GMAC       2
#define SIGNING_ALG_AES_GMAC_LE    cpu_to_le16(2)

struct smb2_signing_capabilities {
	__le16	ContextType; /* 8 */
	__le16	DataLength;
	__le32	Reserved;
	__le16	SigningAlgorithmCount;
	__le16	SigningAlgorithms[];
	/*  Followed by padding to 8 byte boundary (required by some servers) */
} __packed;

#define POSIX_CTXT_DATA_LEN	16
struct smb2_posix_neg_context {
	__le16	ContextType; /* 0x100 */
	__le16	DataLength;
	__le32	Reserved;
	__u8	Name[16]; /* POSIX ctxt GUID 93AD25509CB411E7B42383DE968BCD7C */
} __packed;

struct smb2_negotiate_req {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 36 */
	__le16 DialectCount;
	__le16 SecurityMode;
	__le16 Reserved;	/* MBZ */
	__le32 Capabilities;
	__u8   ClientGUID[SMB2_CLIENT_GUID_SIZE];
	/* In SMB3.02 and earlier next three were MBZ le64 ClientStartTime */
	__le32 NegotiateContextOffset; /* SMB3.1.1 only. MBZ earlier */
	__le16 NegotiateContextCount;  /* SMB3.1.1 only. MBZ earlier */
	__le16 Reserved2;
	__le16 Dialects[];
} __packed;

struct smb2_negotiate_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 65 */
	__le16 SecurityMode;
	__le16 DialectRevision;
	__le16 NegotiateContextCount;	/* Prior to SMB3.1.1 was Reserved & MBZ */
	__u8   ServerGUID[16];
	__le32 Capabilities;
	__le32 MaxTransactSize;
	__le32 MaxReadSize;
	__le32 MaxWriteSize;
	__le64 SystemTime;	/* MBZ */
	__le64 ServerStartTime;
	__le16 SecurityBufferOffset;
	__le16 SecurityBufferLength;
	__le32 NegotiateContextOffset;	/* Pre:SMB3.1.1 was reserved/ignored */
	__u8   Buffer[1];	/* variable length GSS security buffer */
} __packed;


/*
 * SMB2_SESSION_SETUP  See MS-SMB2 section 2.2.5
 */
/* Flags */
#define SMB2_SESSION_REQ_FLAG_BINDING		0x01
#define SMB2_SESSION_REQ_FLAG_ENCRYPT_DATA	0x04

struct smb2_sess_setup_req {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 25 */
	__u8   Flags;
	__u8   SecurityMode;
	__le32 Capabilities;
	__le32 Channel;
	__le16 SecurityBufferOffset;
	__le16 SecurityBufferLength;
	__le64 PreviousSessionId;
	__u8   Buffer[1];	/* variable length GSS security buffer */
} __packed;

/* Currently defined SessionFlags */
#define SMB2_SESSION_FLAG_IS_GUEST        0x0001
#define SMB2_SESSION_FLAG_IS_GUEST_LE     cpu_to_le16(0x0001)
#define SMB2_SESSION_FLAG_IS_NULL         0x0002
#define SMB2_SESSION_FLAG_IS_NULL_LE      cpu_to_le16(0x0002)
#define SMB2_SESSION_FLAG_ENCRYPT_DATA    0x0004
#define SMB2_SESSION_FLAG_ENCRYPT_DATA_LE cpu_to_le16(0x0004)

struct smb2_sess_setup_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 9 */
	__le16 SessionFlags;
	__le16 SecurityBufferOffset;
	__le16 SecurityBufferLength;
	__u8   Buffer[1];	/* variable length GSS security buffer */
} __packed;


/*
 * SMB2_LOGOFF  See MS-SMB2 section 2.2.7
 */
struct smb2_logoff_req {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 4 */
	__le16 Reserved;
} __packed;

struct smb2_logoff_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 4 */
	__le16 Reserved;
} __packed;


/*
 * SMB2_CLOSE  See MS-SMB2 section 2.2.15
 */
/* Currently defined values for close flags */
#define SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB	cpu_to_le16(0x0001)
struct smb2_close_req {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 24 */
	__le16 Flags;
	__le32 Reserved;
	__le64  PersistentFileId; /* opaque endianness */
	__le64  VolatileFileId; /* opaque endianness */
} __packed;

/*
 * Maximum size of a SMB2_CLOSE response is 64 (smb2 header) + 60 (data)
 */
#define MAX_SMB2_CLOSE_RESPONSE_SIZE 124

struct smb2_close_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* 60 */
	__le16 Flags;
	__le32 Reserved;
	__le64 CreationTime;
	__le64 LastAccessTime;
	__le64 LastWriteTime;
	__le64 ChangeTime;
	__le64 AllocationSize;	/* Beginning of FILE_STANDARD_INFO equivalent */
	__le64 EndOfFile;
	__le32 Attributes;
} __packed;


/*
 * SMB2_READ  See MS-SMB2 section 2.2.19
 */
/* For read request Flags field below, following flag is defined for SMB3.02 */
#define SMB2_READFLAG_READ_UNBUFFERED	0x01
#define SMB2_READFLAG_REQUEST_COMPRESSED 0x02 /* See MS-SMB2 2.2.19 */

/* Channel field for read and write: exactly one of following flags can be set*/
#define SMB2_CHANNEL_NONE               cpu_to_le32(0x00000000)
#define SMB2_CHANNEL_RDMA_V1            cpu_to_le32(0x00000001)
#define SMB2_CHANNEL_RDMA_V1_INVALIDATE cpu_to_le32(0x00000002)
#define SMB2_CHANNEL_RDMA_TRANSFORM     cpu_to_le32(0x00000003)

/* SMB2 read request without RFC1001 length at the beginning */
struct smb2_read_req {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 49 */
	__u8   Padding; /* offset from start of SMB2 header to place read */
	__u8   Flags; /* MBZ unless SMB3.02 or later */
	__le32 Length;
	__le64 Offset;
	__le64  PersistentFileId;
	__le64  VolatileFileId;
	__le32 MinimumCount;
	__le32 Channel; /* MBZ except for SMB3 or later */
	__le32 RemainingBytes;
	__le16 ReadChannelInfoOffset;
	__le16 ReadChannelInfoLength;
	__u8   Buffer[1];
} __packed;

/* Read flags */
#define SMB2_READFLAG_RESPONSE_NONE            cpu_to_le32(0x00000000)
#define SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM  cpu_to_le32(0x00000001)

struct smb2_read_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 17 */
	__u8   DataOffset;
	__u8   Reserved;
	__le32 DataLength;
	__le32 DataRemaining;
	__le32 Flags;
	__u8   Buffer[1];
} __packed;


/*
 * SMB2_WRITE  See MS-SMB2 section 2.2.21
 */
/* For write request Flags field below the following flags are defined: */
#define SMB2_WRITEFLAG_WRITE_THROUGH	0x00000001	/* SMB2.1 or later */
#define SMB2_WRITEFLAG_WRITE_UNBUFFERED	0x00000002	/* SMB3.02 or later */

struct smb2_write_req {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 49 */
	__le16 DataOffset; /* offset from start of SMB2 header to write data */
	__le32 Length;
	__le64 Offset;
	__le64  PersistentFileId; /* opaque endianness */
	__le64  VolatileFileId; /* opaque endianness */
	__le32 Channel; /* MBZ unless SMB3.02 or later */
	__le32 RemainingBytes;
	__le16 WriteChannelInfoOffset;
	__le16 WriteChannelInfoLength;
	__le32 Flags;
	__u8   Buffer[1];
} __packed;

struct smb2_write_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize; /* Must be 17 */
	__u8   DataOffset;
	__u8   Reserved;
	__le32 DataLength;
	__le32 DataRemaining;
	__u32  Reserved2;
	__u8   Buffer[1];
} __packed;


/*
 * SMB2_FLUSH  See MS-SMB2 section 2.2.17
 */
struct smb2_flush_req {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 24 */
	__le16 Reserved1;
	__le32 Reserved2;
	__le64  PersistentFileId;
	__le64  VolatileFileId;
} __packed;

struct smb2_flush_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize;
	__le16 Reserved;
} __packed;


/*
 * SMB2_NOTIFY  See MS-SMB2 section 2.2.35
 */
/* notify flags */
#define SMB2_WATCH_TREE			0x0001

/* notify completion filter flags. See MS-FSCC 2.6 and MS-SMB2 2.2.35 */
#define FILE_NOTIFY_CHANGE_FILE_NAME		0x00000001
#define FILE_NOTIFY_CHANGE_DIR_NAME		0x00000002
#define FILE_NOTIFY_CHANGE_ATTRIBUTES		0x00000004
#define FILE_NOTIFY_CHANGE_SIZE			0x00000008
#define FILE_NOTIFY_CHANGE_LAST_WRITE		0x00000010
#define FILE_NOTIFY_CHANGE_LAST_ACCESS		0x00000020
#define FILE_NOTIFY_CHANGE_CREATION		0x00000040
#define FILE_NOTIFY_CHANGE_EA			0x00000080
#define FILE_NOTIFY_CHANGE_SECURITY		0x00000100
#define FILE_NOTIFY_CHANGE_STREAM_NAME		0x00000200
#define FILE_NOTIFY_CHANGE_STREAM_SIZE		0x00000400
#define FILE_NOTIFY_CHANGE_STREAM_WRITE		0x00000800

/* SMB2 Notify Action Flags */
#define FILE_ACTION_ADDED                       0x00000001
#define FILE_ACTION_REMOVED                     0x00000002
#define FILE_ACTION_MODIFIED                    0x00000003
#define FILE_ACTION_RENAMED_OLD_NAME            0x00000004
#define FILE_ACTION_RENAMED_NEW_NAME            0x00000005
#define FILE_ACTION_ADDED_STREAM                0x00000006
#define FILE_ACTION_REMOVED_STREAM              0x00000007
#define FILE_ACTION_MODIFIED_STREAM             0x00000008
#define FILE_ACTION_REMOVED_BY_DELETE           0x00000009

struct smb2_change_notify_req {
	struct smb2_hdr hdr;
	__le16	StructureSize;
	__le16	Flags;
	__le32	OutputBufferLength;
	__le64	PersistentFileId; /* opaque endianness */
	__le64	VolatileFileId; /* opaque endianness */
	__le32	CompletionFilter;
	__u32	Reserved;
} __packed;

struct smb2_change_notify_rsp {
	struct smb2_hdr hdr;
	__le16	StructureSize;  /* Must be 9 */
	__le16	OutputBufferOffset;
	__le32	OutputBufferLength;
	__u8	Buffer[1]; /* array of file notify structs */
} __packed;


/*
 * SMB2_CREATE  See MS-SMB2 section 2.2.13
 */
/* Oplock levels */
#define SMB2_OPLOCK_LEVEL_NONE		0x00
#define SMB2_OPLOCK_LEVEL_II		0x01
#define SMB2_OPLOCK_LEVEL_EXCLUSIVE	0x08
#define SMB2_OPLOCK_LEVEL_BATCH		0x09
#define SMB2_OPLOCK_LEVEL_LEASE		0xFF
/* Non-spec internal type */
#define SMB2_OPLOCK_LEVEL_NOCHANGE	0x99

/* Impersonation Levels. See MS-WPO section 9.7 and MSDN-IMPERS */
#define IL_ANONYMOUS		cpu_to_le32(0x00000000)
#define IL_IDENTIFICATION	cpu_to_le32(0x00000001)
#define IL_IMPERSONATION	cpu_to_le32(0x00000002)
#define IL_DELEGATE		cpu_to_le32(0x00000003)

/* File Attrubutes */
#define FILE_ATTRIBUTE_READONLY			0x00000001
#define FILE_ATTRIBUTE_HIDDEN			0x00000002
#define FILE_ATTRIBUTE_SYSTEM			0x00000004
#define FILE_ATTRIBUTE_DIRECTORY		0x00000010
#define FILE_ATTRIBUTE_ARCHIVE			0x00000020
#define FILE_ATTRIBUTE_NORMAL			0x00000080
#define FILE_ATTRIBUTE_TEMPORARY		0x00000100
#define FILE_ATTRIBUTE_SPARSE_FILE		0x00000200
#define FILE_ATTRIBUTE_REPARSE_POINT		0x00000400
#define FILE_ATTRIBUTE_COMPRESSED		0x00000800
#define FILE_ATTRIBUTE_OFFLINE			0x00001000
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED	0x00002000
#define FILE_ATTRIBUTE_ENCRYPTED		0x00004000
#define FILE_ATTRIBUTE_INTEGRITY_STREAM		0x00008000
#define FILE_ATTRIBUTE_NO_SCRUB_DATA		0x00020000
#define FILE_ATTRIBUTE__MASK			0x00007FB7

#define FILE_ATTRIBUTE_READONLY_LE              cpu_to_le32(0x00000001)
#define FILE_ATTRIBUTE_HIDDEN_LE		cpu_to_le32(0x00000002)
#define FILE_ATTRIBUTE_SYSTEM_LE		cpu_to_le32(0x00000004)
#define FILE_ATTRIBUTE_DIRECTORY_LE		cpu_to_le32(0x00000010)
#define FILE_ATTRIBUTE_ARCHIVE_LE		cpu_to_le32(0x00000020)
#define FILE_ATTRIBUTE_NORMAL_LE		cpu_to_le32(0x00000080)
#define FILE_ATTRIBUTE_TEMPORARY_LE		cpu_to_le32(0x00000100)
#define FILE_ATTRIBUTE_SPARSE_FILE_LE		cpu_to_le32(0x00000200)
#define FILE_ATTRIBUTE_REPARSE_POINT_LE		cpu_to_le32(0x00000400)
#define FILE_ATTRIBUTE_COMPRESSED_LE		cpu_to_le32(0x00000800)
#define FILE_ATTRIBUTE_OFFLINE_LE		cpu_to_le32(0x00001000)
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED_LE	cpu_to_le32(0x00002000)
#define FILE_ATTRIBUTE_ENCRYPTED_LE		cpu_to_le32(0x00004000)
#define FILE_ATTRIBUTE_INTEGRITY_STREAM_LE	cpu_to_le32(0x00008000)
#define FILE_ATTRIBUTE_NO_SCRUB_DATA_LE		cpu_to_le32(0x00020000)
#define FILE_ATTRIBUTE_MASK_LE			cpu_to_le32(0x00007FB7)

/* Desired Access Flags */
#define FILE_READ_DATA_LE		cpu_to_le32(0x00000001)
#define FILE_LIST_DIRECTORY_LE		cpu_to_le32(0x00000001)
#define FILE_WRITE_DATA_LE		cpu_to_le32(0x00000002)
#define FILE_APPEND_DATA_LE		cpu_to_le32(0x00000004)
#define FILE_ADD_SUBDIRECTORY_LE	cpu_to_le32(0x00000004)
#define FILE_READ_EA_LE			cpu_to_le32(0x00000008)
#define FILE_WRITE_EA_LE		cpu_to_le32(0x00000010)
#define FILE_EXECUTE_LE			cpu_to_le32(0x00000020)
#define FILE_DELETE_CHILD_LE		cpu_to_le32(0x00000040)
#define FILE_READ_ATTRIBUTES_LE		cpu_to_le32(0x00000080)
#define FILE_WRITE_ATTRIBUTES_LE	cpu_to_le32(0x00000100)
#define FILE_DELETE_LE			cpu_to_le32(0x00010000)
#define FILE_READ_CONTROL_LE		cpu_to_le32(0x00020000)
#define FILE_WRITE_DAC_LE		cpu_to_le32(0x00040000)
#define FILE_WRITE_OWNER_LE		cpu_to_le32(0x00080000)
#define FILE_SYNCHRONIZE_LE		cpu_to_le32(0x00100000)
#define FILE_ACCESS_SYSTEM_SECURITY_LE	cpu_to_le32(0x01000000)
#define FILE_MAXIMAL_ACCESS_LE		cpu_to_le32(0x02000000)
#define FILE_GENERIC_ALL_LE		cpu_to_le32(0x10000000)
#define FILE_GENERIC_EXECUTE_LE		cpu_to_le32(0x20000000)
#define FILE_GENERIC_WRITE_LE		cpu_to_le32(0x40000000)
#define FILE_GENERIC_READ_LE		cpu_to_le32(0x80000000)
#define DESIRED_ACCESS_MASK             cpu_to_le32(0xF21F01FF)


#define FILE_READ_DESIRED_ACCESS_LE     (FILE_READ_DATA_LE        |	\
					 FILE_READ_EA_LE          |     \
					 FILE_GENERIC_READ_LE)
#define FILE_WRITE_DESIRE_ACCESS_LE     (FILE_WRITE_DATA_LE       |	\
					 FILE_APPEND_DATA_LE      |	\
					 FILE_WRITE_EA_LE         |	\
					 FILE_WRITE_ATTRIBUTES_LE |	\
					 FILE_GENERIC_WRITE_LE)

/* ShareAccess Flags */
#define FILE_SHARE_READ_LE		cpu_to_le32(0x00000001)
#define FILE_SHARE_WRITE_LE		cpu_to_le32(0x00000002)
#define FILE_SHARE_DELETE_LE		cpu_to_le32(0x00000004)
#define FILE_SHARE_ALL_LE		cpu_to_le32(0x00000007)

/* CreateDisposition Flags */
#define FILE_SUPERSEDE_LE		cpu_to_le32(0x00000000)
#define FILE_OPEN_LE			cpu_to_le32(0x00000001)
#define FILE_CREATE_LE			cpu_to_le32(0x00000002)
#define	FILE_OPEN_IF_LE			cpu_to_le32(0x00000003)
#define FILE_OVERWRITE_LE		cpu_to_le32(0x00000004)
#define FILE_OVERWRITE_IF_LE		cpu_to_le32(0x00000005)
#define FILE_CREATE_MASK_LE             cpu_to_le32(0x00000007)

#define FILE_READ_RIGHTS (FILE_READ_DATA | FILE_READ_EA \
			| FILE_READ_ATTRIBUTES)
#define FILE_WRITE_RIGHTS (FILE_WRITE_DATA | FILE_APPEND_DATA \
			| FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES)
#define FILE_EXEC_RIGHTS (FILE_EXECUTE)

/* CreateOptions Flags */
#define FILE_DIRECTORY_FILE_LE		cpu_to_le32(0x00000001)
/* same as #define CREATE_NOT_FILE_LE	cpu_to_le32(0x00000001) */
#define FILE_WRITE_THROUGH_LE		cpu_to_le32(0x00000002)
#define FILE_SEQUENTIAL_ONLY_LE		cpu_to_le32(0x00000004)
#define FILE_NO_INTERMEDIATE_BUFFERING_LE cpu_to_le32(0x00000008)
#define FILE_NON_DIRECTORY_FILE_LE	cpu_to_le32(0x00000040)
#define FILE_COMPLETE_IF_OPLOCKED_LE	cpu_to_le32(0x00000100)
#define FILE_NO_EA_KNOWLEDGE_LE		cpu_to_le32(0x00000200)
#define FILE_RANDOM_ACCESS_LE		cpu_to_le32(0x00000800)
#define FILE_DELETE_ON_CLOSE_LE		cpu_to_le32(0x00001000)
#define FILE_OPEN_BY_FILE_ID_LE		cpu_to_le32(0x00002000)
#define FILE_OPEN_FOR_BACKUP_INTENT_LE	cpu_to_le32(0x00004000)
#define FILE_NO_COMPRESSION_LE		cpu_to_le32(0x00008000)
#define FILE_OPEN_REPARSE_POINT_LE	cpu_to_le32(0x00200000)
#define FILE_OPEN_NO_RECALL_LE		cpu_to_le32(0x00400000)
#define CREATE_OPTIONS_MASK_LE          cpu_to_le32(0x00FFFFFF)

#define FILE_READ_RIGHTS_LE (FILE_READ_DATA_LE | FILE_READ_EA_LE \
			| FILE_READ_ATTRIBUTES_LE)
#define FILE_WRITE_RIGHTS_LE (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE \
			| FILE_WRITE_EA_LE | FILE_WRITE_ATTRIBUTES_LE)
#define FILE_EXEC_RIGHTS_LE (FILE_EXECUTE_LE)

/* Create Context Values */
#define SMB2_CREATE_EA_BUFFER			"ExtA" /* extended attributes */
#define SMB2_CREATE_SD_BUFFER			"SecD" /* security descriptor */
#define SMB2_CREATE_DURABLE_HANDLE_REQUEST	"DHnQ"
#define SMB2_CREATE_DURABLE_HANDLE_RECONNECT	"DHnC"
#define SMB2_CREATE_ALLOCATION_SIZE		"AISi"
#define SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST "MxAc"
#define SMB2_CREATE_TIMEWARP_REQUEST		"TWrp"
#define SMB2_CREATE_QUERY_ON_DISK_ID		"QFid"
#define SMB2_CREATE_REQUEST_LEASE		"RqLs"
#define SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2	"DH2Q"
#define SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2	"DH2C"
#define SMB2_CREATE_TAG_POSIX          "\x93\xAD\x25\x50\x9C\xB4\x11\xE7\xB4\x23\x83\xDE\x96\x8B\xCD\x7C"

/* Flag (SMB3 open response) values */
#define SMB2_CREATE_FLAG_REPARSEPOINT 0x01

struct create_context {
	__le32 Next;
	__le16 NameOffset;
	__le16 NameLength;
	__le16 Reserved;
	__le16 DataOffset;
	__le32 DataLength;
	__u8 Buffer[];
} __packed;

struct smb2_create_req {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 57 */
	__u8   SecurityFlags;
	__u8   RequestedOplockLevel;
	__le32 ImpersonationLevel;
	__le64 SmbCreateFlags;
	__le64 Reserved;
	__le32 DesiredAccess;
	__le32 FileAttributes;
	__le32 ShareAccess;
	__le32 CreateDisposition;
	__le32 CreateOptions;
	__le16 NameOffset;
	__le16 NameLength;
	__le32 CreateContextsOffset;
	__le32 CreateContextsLength;
	__u8   Buffer[];
} __packed;

struct smb2_create_rsp {
	struct smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 89 */
	__u8   OplockLevel;
	__u8   Flags;  /* 0x01 if reparse point */
	__le32 CreateAction;
	__le64 CreationTime;
	__le64 LastAccessTime;
	__le64 LastWriteTime;
	__le64 ChangeTime;
	__le64 AllocationSize;
	__le64 EndofFile;
	__le32 FileAttributes;
	__le32 Reserved2;
	__le64  PersistentFileId;
	__le64  VolatileFileId;
	__le32 CreateContextsOffset;
	__le32 CreateContextsLength;
	__u8   Buffer[1];
} __packed;


#endif				/* _COMMON_SMB2PDU_H */
