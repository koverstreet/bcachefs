/**
 * Copyright (c) 2016-present, Yann Collet, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. An additional grant
 * of patent rights can be found in the PATENTS file in the same directory.
 */



/*-*************************************
*  Dependencies
***************************************/
#include "error_private.h"
#define ZSTD_STATIC_LINKING_ONLY
#include <linux/zstd.h>


/*-****************************************
*  ZSTD Error Management
******************************************/
/*! ZSTD_isError() :
*   tells if a return value is an error code */
unsigned ZSTD_isError(size_t code) { return ERR_isError(code); }

/*! ZSTD_getErrorName() :
*   provides error code string from function result (useful for debugging) */
const char* ZSTD_getErrorName(size_t code) { return ERR_getErrorName(code); }

/*! ZSTD_getError() :
*   convert a `size_t` function result into a proper ZSTD_errorCode enum */
ZSTD_ErrorCode ZSTD_getErrorCode(size_t code) { return ERR_getErrorCode(code); }

/*! ZSTD_getErrorString() :
*   provides error code string from enum */
const char* ZSTD_getErrorString(ZSTD_ErrorCode code) { return ERR_getErrorName(code); }
