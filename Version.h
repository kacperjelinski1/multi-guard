// ═══════════════════════════════════════════════════════════════════════
//  VeraxCore Antivirus — single source of truth for identity, version,
//  paths, URLs. Edit ONLY the macros below.
//  By Ali Sakkaf  •  https://alisakkaf.com
// ═══════════════════════════════════════════════════════════════════════
#pragma once

// ─── Identity ──────────────────────────────────────────────────────────
#define APP_NAME            "Multi-Guard"
#define APP_NAME_SHORT      "Multi-Guard"
#define APP_TAGLINE         "Real protection. Zero noise."
#define APP_VENDOR          "Multi-Servis"
#define APP_DESCRIPTION     "Multi-Guard - inteligentna ochrona i integralność komputera."
#define APP_COPYRIGHT       "Copyright (c) 2026 Multi-Servis"
#define APP_HOMEPAGE        "https://multi-servis.pl"
#define APP_AUTHOR_FB       "https://facebook.com/MultiServis"
#define APP_AUTHOR_GH       "https://github.com/MultiServis"

// ─── Version (single source of truth) ─────────────────────────────────
#define APP_VERSION_MAJOR   1
#define APP_VERSION_MINOR   1
#define APP_VERSION_PATCH   5
#define APP_VERSION_BUILD   0

// Auto-derived — DO NOT EDIT BELOW
#define _VR_STR(x) #x
#define _VR_S(x) _VR_STR(x)
#define APP_VERSION_STR \
_VR_S(APP_VERSION_MAJOR) "." _VR_S(APP_VERSION_MINOR) "." \
    _VR_S(APP_VERSION_PATCH) "." _VR_S(APP_VERSION_BUILD)
#define APP_VERSION_RC \
    APP_VERSION_MAJOR,APP_VERSION_MINOR,APP_VERSION_PATCH,APP_VERSION_BUILD

// ─── Install paths (Removed custom author name subdirectories) ────────
#define APP_INSTALL_DIR     "C:\\Program Files\\Multi-Guard"
#define APP_BIN_NAME        "Multi-Guard.exe"
#define APP_REG_KEY         "SOFTWARE\\Multi-Servis\\Multi-Guard"
#define APP_VAULT_SUBDIR    "Vault"
#define APP_LOG_SUBDIR      "Logs"

// ─── Network endpoints ─────────────────────────────────────────────────
#define APP_UPDATE_URL          "https://raw.githubusercontent.com/kacperjelinski1/multi-guard/main/updates/signatures.json"
#define APP_VERSION_CHECK_URL   "https://raw.githubusercontent.com/kacperjelinski1/multi-guard/main/updates/version.txt"
#define APP_DOWNLOAD_URL        "https://github.com/kacperjelinski1/multi-guard/releases/latest"

// ─── Theme ────────────────────────────────────────────────────────────
#define APP_THEME           "Dark"
