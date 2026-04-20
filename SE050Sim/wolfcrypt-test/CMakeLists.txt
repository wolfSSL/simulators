# Build the NXP Plug&Trust SDK sources into the static libraries
# that wolfSSL's configure expects at specific paths under build/.
CMAKE_MINIMUM_REQUIRED(VERSION 3.5.0)
project(se050_sdk_libs)

SET(SIMW_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR})
INCLUDE(${SIMW_LIB_DIR}/simw_lib.cmake)

# 1. libSSS_APIs.a in build/sss/
#
# HostCrypto backend is picked by PTMW_HostCrypto (set at cmake configure):
#   OPENSSL  → sss/src/openssl/fsl_sss_openssl_apis.c (sdk-test uses this)
#   WOLFSSL  → sss/src/wolfssl/fsl_sss_wolfssl_apis.c, added by wolfSSL's OSP
#              middleware patch (wolfcrypt-test uses this)
FILE(GLOB SSS_SOURCES
    ${SIMW_LIB_DIR}/sss/src/*.c
    ${SIMW_LIB_DIR}/sss/src/se05x/*.c
    ${SIMW_LIB_DIR}/sss/src/keystore/*.c
)
IF("${PTMW_HostCrypto}" STREQUAL "WOLFSSL")
    LIST(APPEND SSS_SOURCES ${SIMW_LIB_DIR}/sss/src/wolfssl/fsl_sss_wolfssl_apis.c)
ELSE()
    LIST(APPEND SSS_SOURCES ${SIMW_LIB_DIR}/sss/src/openssl/fsl_sss_openssl_apis.c)
ENDIF()
ADD_LIBRARY(SSS_APIs STATIC ${SSS_SOURCES})
TARGET_INCLUDE_DIRECTORIES(SSS_APIs PUBLIC ${SIMW_INC_DIR})
IF("${PTMW_HostCrypto}" STREQUAL "WOLFSSL")
    TARGET_LINK_LIBRARIES(SSS_APIs PUBLIC wolfssl)
ENDIF()
SET_TARGET_PROPERTIES(SSS_APIs PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/sss)

# 2. libex_common.a in build/sss/ex/src/
FILE(GLOB EX_SOURCES
    ${SIMW_LIB_DIR}/sss/ex/src/ex_sss_boot.c
    ${SIMW_LIB_DIR}/sss/ex/src/ex_sss_boot_connectstring.c
    ${SIMW_LIB_DIR}/sss/ex/src/ex_sss_se05x.c
    ${SIMW_LIB_DIR}/sss/ex/src/ex_sss_se05x_auth.c
)
ADD_LIBRARY(ex_common STATIC ${EX_SOURCES})
TARGET_INCLUDE_DIRECTORIES(ex_common PUBLIC ${SIMW_INC_DIR})
SET_TARGET_PROPERTIES(ex_common PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/sss/ex/src)

# 3. libse05x.a in build/hostlib/hostLib/se05x/
FILE(GLOB SE05X_SOURCES
    ${SIMW_LIB_DIR}/hostlib/hostLib/se05x/src/*.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/se05x_03_xx_xx/*.c
)
ADD_LIBRARY(se05x STATIC ${SE05X_SOURCES})
TARGET_INCLUDE_DIRECTORIES(se05x PUBLIC ${SIMW_INC_DIR})
SET_TARGET_PROPERTIES(se05x PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/hostlib/hostLib/se05x)

# 4. liba7x_utils.a in build/hostlib/hostLib/
FILE(GLOB A7X_SOURCES
    ${SIMW_LIB_DIR}/hostlib/hostLib/platform/linux/i2c_a7.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/platform/rsp/se05x_reset.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/platform/generic/sm_timer.c
)
ADD_LIBRARY(a7x_utils STATIC ${A7X_SOURCES})
TARGET_INCLUDE_DIRECTORIES(a7x_utils PUBLIC ${SIMW_INC_DIR})
SET_TARGET_PROPERTIES(a7x_utils PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/hostlib/hostLib)

# 5. libmwlog.a in build/hostlib/hostLib/libCommon/log/
ADD_LIBRARY(mwlog STATIC ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/log/nxLog.c)
TARGET_INCLUDE_DIRECTORIES(mwlog PUBLIC ${SIMW_INC_DIR})
SET_TARGET_PROPERTIES(mwlog PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/hostlib/hostLib/libCommon/log)

# 6. libsmCom.a in build/hostlib/hostLib/libCommon/
FILE(GLOB SMCOM_SOURCES
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/smCom/smCom.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/smCom/smComT1oI2C.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/smCom/T1oI2C/*.c
    ${SIMW_LIB_DIR}/hostlib/hostLib/libCommon/infra/*.c
)
ADD_LIBRARY(smCom STATIC ${SMCOM_SOURCES})
TARGET_INCLUDE_DIRECTORIES(smCom PUBLIC ${SIMW_INC_DIR})
SET_TARGET_PROPERTIES(smCom PROPERTIES ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/hostlib/hostLib/libCommon)
