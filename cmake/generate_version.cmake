set(VERSION_FILE "${FASTD_BINARY_DIR}/src/fastd_version.h")

add_custom_target(
    version
    COMMAND echo "#pragma once" > "${VERSION_FILE}.new"
    COMMAND sh -c "echo \"#define FASTD_VERSION \\\"$(git --git-dir=./.git describe --dirty 2>/dev/null || echo ${FASTD_VERSION})\\\"\"" >> "${VERSION_FILE}.new"
    COMMAND cmp -s "${VERSION_FILE}" "${VERSION_FILE}.new" && rm "${VERSION_FILE}.new" || mv "${VERSION_FILE}.new" "${VERSION_FILE}"
    WORKING_DIRECTORY "${FASTD_SOURCE_DIR}"
    VERBATIM
)
set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "${VERSION_FILE}")
