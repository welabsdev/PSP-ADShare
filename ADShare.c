
#include <pspkernel.h>
#include <pspdisplay.h>
#include <pspctrl.h>
#include <pspiofilemgr.h>
#include <pspnet.h>
#include <pspnet_adhoc.h>
#include <pspnet_adhocctl.h>
#include <psputility.h>
#include <psputility_netmodules.h>
#include <psputility_sysparam.h>
#include <pspwlan.h>
#include <pspsysmem.h>
#include <psppower.h>
#include <psprtc.h>
#include <kubridge.h>
#include <libpspexploit.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stddef.h>
#include <oslib/oslib.h>

/*
 * ADShare 2.1.1
 * Compartilhamento direto PSP <-> PSP usando o modo Ad Hoc nativo.
 *
 * - Descoberta de consoles por PDP broadcast.
 * - Oferta de arquivo com aceitar/recusar no PSP receptor.
 * - Transferencia de arquivo por PDP confiavel com ACK, CRC32 e retry.
 * - Fotos, musicas, ISOs/CSOs/ZSOs, PBP e qualquer outro arquivo.
 * - Interface bilingue Portugues (Brasil) / English.
 * - Informacoes do dispositivo, firmware, canal Ad Hoc, MAC, regiao do
 *   sistema, idioma, modelo/SKU e identificadores reais de placa.
 *
 * INFORMACOES DE HARDWARE:
 * Esta versao usa KUBridge para a geracao real do console e LibPspExploit
 * para executar uma rotina curta em kernel e consultar IDStorage,
 * Tachyon, Baryon e Pommel.
 *
 * Nao usa sctrlHENFindFunctionOnSystem, nao usa heuristica de RAM e nao
 * inventa a revisao da placa quando os IDs reais nao forem reconhecidos.
 *
 * A implementacao de leitura dos IDs segue a abordagem publica do pspIdent
 * (Yoti e colaboradores), adaptada para a interface e arquitetura do ADShare.
 */

#define APP_NAME              "ADShare"
#define APP_VERSION           "2.1.1"
#define APP_AUTHOR            "welabsdev"

#define ADHOC_GROUP           "ADSHARE"     /* max. 8 chars */
#define ADHOC_PRODUCT         "ADSHARE01"   /* EXATAMENTE 9 bytes; sem terminador no productStruct */
#define CTRL_PORT             31000
#define DATA_SERVER_PORT      31001
#define DATA_CLIENT_PORT      31002

#define PDP_BUFFER_SIZE       0x4000
#define DATA_PDP_BUFFER_SIZE  0x8000
#define DATA_CHUNK_SIZE       1024
#define DATA_RETRY_COUNT      16
#define DATA_ACK_TIMEOUT_US   1500000u
#define DATA_RECV_TIMEOUT_US  8000000u
#define MAX_PEERS             8
#define MAX_FILES             128
#define PEER_TIMEOUT_US       12000000u
#define HELLO_INTERVAL_US     1000000u
#define OFFER_TIMEOUT_US      30000000u

#define PROTOCOL_MAGIC        "ADSH"
#define PROTOCOL_VERSION      2
#define DATA_MAGIC            "ADD2"
#define DATA_VERSION          2 /* v2.1.1: corrige semantica ret/len do PDP no PSP real */

/* ADHOC_PRODUCT precisa conter exatamente 9 caracteres + NUL do literal. */
typedef char ADShare_ProductId_Must_Be_9_Chars[(sizeof(ADHOC_PRODUCT) == 10) ? 1 : -1];

PSP_MODULE_INFO("ADShare", 0, 2, 2);
PSP_MAIN_THREAD_ATTR(THREAD_ATTR_USER | THREAD_ATTR_VFPU);

/* =========================================================
   CORES / DESIGN - MESMA IDENTIDADE DO BREWLOGY PORTABLE
   ========================================================= */

#define C_BG            RGBA(12, 12, 14, 255)
#define C_BAR_BG        RGBA(20, 20, 24, 255)
#define C_PANEL         RGBA(25, 25, 30, 255)
#define C_PANEL_2       RGBA(31, 31, 37, 255)
#define C_PSN_BLUE      RGBA(0, 112, 204, 255)
#define C_PSN_BLUE_SOFT RGBA(0, 112, 204, 80)
#define C_TEXT          RGBA(240, 240, 240, 255)
#define C_TEXT_DIM      RGBA(145, 145, 155, 255)
#define C_TEXT_DARK     RGBA(98, 98, 108, 255)
#define C_HIGHLIGHT     RGBA(255, 255, 255, 24)
#define C_HIGH_BORDER   RGBA(0, 112, 204, 210)
#define C_SUCCESS       RGBA(65, 205, 105, 255)
#define C_ERROR         RGBA(225, 75, 75, 255)
#define C_WARNING       RGBA(235, 180, 55, 255)
#define C_FOLDER        RGBA(220, 180, 50, 255)
#define C_FOLDER_DARK   RGBA(190, 145, 32, 255)
#define C_SCROLL_BG     RGBA(34, 34, 40, 255)
#define C_SCROLL_BAR    RGBA(150, 150, 160, 255)

/* =========================================================
   PROTOCOLO
   ========================================================= */

enum PacketType {
    PKT_HELLO  = 1,
    PKT_OFFER  = 2,
    PKT_ACCEPT = 3,
    PKT_REJECT = 4,
    PKT_CANCEL = 5,
    PKT_DONE   = 6
};

typedef struct __attribute__((packed)) AdPacket {
    char magic[4];
    uint8_t version;
    uint8_t type;
    uint16_t reserved;
    uint32_t token;
    unsigned char sender_mac[6];
    char nickname[32];
    char device[32];
    char firmware[16];
    uint64_t file_size;
    char file_name[128];
    char file_type[16];
} AdPacket;

enum DataPacketType {
    DATA_PKT_HEADER     = 1,
    DATA_PKT_HEADER_ACK = 2,
    DATA_PKT_CHUNK      = 3,
    DATA_PKT_ACK        = 4,
    DATA_PKT_FIN        = 5,
    DATA_PKT_FIN_ACK    = 6,
    DATA_PKT_CANCEL     = 7
};

typedef struct __attribute__((packed)) DataPacket {
    char magic[4];
    uint8_t version;
    uint8_t type;
    uint16_t payload_len;
    uint32_t token;
    uint32_t seq;
    uint32_t crc32;
    uint64_t file_size;
    char file_name[128];
    unsigned char payload[DATA_CHUNK_SIZE];
} DataPacket;

#define DATA_PACKET_BASE_SIZE ((int)offsetof(DataPacket, payload))

typedef struct PeerInfo {
    int used;
    unsigned char mac[6];
    char nickname[32];
    char device[32];
    char firmware[16];
    uint32_t last_seen;
} PeerInfo;

typedef struct FileEntry {
    char name[256];
    int is_dir;
    SceOff size;
} FileEntry;

typedef struct DeviceInfo {
    char nickname[128];
    char firmware[24];
    char model[64];
    char generation[16];
    char board_family[96];
    char region[64];
    char language[32];
    char mac[32];
    char adhoc_channel[32];
    char kernel_source[64];

    char region_id_text[32];
    char tachyon_text[32];
    char baryon_text[32];
    char pommel_text[32];
    char probe_status_text[64];

    int model_generation;
    int kernel_model_result;

    int region_valid;
    uint8_t region_id;

    int tachyon_valid;
    int baryon_valid;
    int pommel_valid;
    uint32_t tachyon;
    uint32_t baryon;
    uint32_t pommel;
} DeviceInfo;

/* =========================================================
   ESTADO GLOBAL
   ========================================================= */

static OSL_FONT* g_font = NULL;

/* Etapas separadas para permitir cleanup seguro em falhas parciais. */
static int g_net_initialized = 0;
static int g_adhoc_initialized = 0;
static int g_adhocctl_initialized = 0;
static int g_adhoc_connected = 0;
static int g_pdp_id = -1;
static unsigned char g_local_mac[6] = {0};
static char g_local_nickname[128] = "PSP";
static char g_connected_group[16] = ADHOC_GROUP;
static int g_connected_channel = 0;
static DeviceInfo g_device;

static PeerInfo g_peers[MAX_PEERS];
static int g_peer_count = 0;
static int g_selected_peer = 0;

static int g_has_pending_offer = 0;
static AdPacket g_pending_offer;
static unsigned char g_pending_offer_mac[6];

static uint32_t g_outgoing_token = 0;
static int g_outgoing_response = 0; /* 0 aguardando, 1 aceito, -1 recusado */
static unsigned char g_outgoing_peer_mac[6];
static int g_outgoing_waiting = 0;
static int g_transfer_busy = 0;

static uint32_t g_last_hello = 0;
static char g_status_line[128] = "Pronto";

enum UiLanguage {
    UI_LANG_PTBR = 0,
    UI_LANG_EN   = 1
};

static int g_ui_language = UI_LANG_PTBR;

static const char* ui_text(const char* ptbr, const char* en)
{
    return g_ui_language == UI_LANG_EN ? en : ptbr;
}

static void init_ui_language(void)
{
    int lang = PSP_SYSTEMPARAM_LANGUAGE_PORTUGUESE;

    if (sceUtilityGetSystemParamInt(
            PSP_SYSTEMPARAM_ID_INT_LANGUAGE, &lang) < 0) {
        g_ui_language = UI_LANG_PTBR;
        return;
    }

    g_ui_language =
        (lang == PSP_SYSTEMPARAM_LANGUAGE_PORTUGUESE)
        ? UI_LANG_PTBR
        : UI_LANG_EN;
}

static void toggle_ui_language(void)
{
    g_ui_language =
        (g_ui_language == UI_LANG_PTBR)
        ? UI_LANG_EN
        : UI_LANG_PTBR;
}

/* =========================================================
   CALLBACKS
   ========================================================= */

static int exit_callback(int arg1, int arg2, void* common)
{
    (void)arg1;
    (void)arg2;
    (void)common;
    oslQuit();
    return 0;
}

static int callback_thread(SceSize args, void* argp)
{
    (void)args;
    (void)argp;
    int cbid = sceKernelCreateCallback("ADShare Exit", exit_callback, NULL);
    sceKernelRegisterExitCallback(cbid);
    sceKernelSleepThreadCB();
    return 0;
}

static void setup_callbacks(void)
{
    int thid = sceKernelCreateThread(
        "ADShareCallbacks",
        callback_thread,
        0x11,
        0xFA0,
        PSP_THREAD_ATTR_USER,
        NULL
    );

    if (thid >= 0)
        sceKernelStartThread(thid, 0, NULL);
}

/* =========================================================
   HELPERS GERAIS
   ========================================================= */

static uint32_t now_us(void)
{
    return (uint32_t)sceKernelGetSystemTimeLow();
}

static int elapsed_us(uint32_t start, uint32_t interval)
{
    return (uint32_t)(now_us() - start) >= interval;
}

static void safe_copy(char* dst, const char* src, int dst_size)
{
    size_t len;

    if (!dst || dst_size <= 0)
        return;

    if (!src)
        src = "";

    len = strlen(src);
    if (len >= (size_t)dst_size)
        len = (size_t)dst_size - 1;

    if (len > 0)
        memcpy(dst, src, len);

    dst[len] = '\0';
}

/* Acrescenta texto sem ultrapassar o buffer. Retorna 1 se coube inteiro. */
static void set_status(const char* ptbr, const char* en)
{
    safe_copy(g_status_line, ui_text(ptbr, en), sizeof(g_status_line));
}

static void set_status_error(const char* ptbr, const char* en, int error)
{
    char text[128];

    if (error < 0) {
        snprintf(
            text,
            sizeof(text),
            "%s 0x%08X",
            ui_text(ptbr, en),
            (unsigned int)error
        );
    } else {
        snprintf(
            text,
            sizeof(text),
            "%s %s",
            ui_text(ptbr, en),
            ui_text("(sem resposta)", "(no response)")
        );
    }

    safe_copy(g_status_line, text, sizeof(g_status_line));
}

static int safe_append(char* dst, const char* src, int dst_size)
{
    size_t used;
    size_t available;
    size_t len;
    int complete = 1;

    if (!dst || dst_size <= 0)
        return 0;

    if (!src)
        src = "";

    used = strlen(dst);
    if (used >= (size_t)dst_size) {
        dst[dst_size - 1] = '\0';
        return 0;
    }

    available = (size_t)dst_size - used - 1;
    len = strlen(src);

    if (len > available) {
        len = available;
        complete = 0;
    }

    if (len > 0)
        memcpy(dst + used, src, len);

    dst[used + len] = '\0';
    return complete;
}

static int mac_equal(const unsigned char* a, const unsigned char* b)
{
    return memcmp(a, b, 6) == 0;
}

static void mac_to_string(const unsigned char* mac, char* out, int out_size)
{
    snprintf(out, out_size,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void format_size(uint64_t size, char* out, int out_size)
{
    if (size >= 1073741824ULL)
        snprintf(out, out_size, "%.2f GB", (double)size / 1073741824.0);
    else if (size >= 1048576ULL)
        snprintf(out, out_size, "%.2f MB", (double)size / 1048576.0);
    else if (size >= 1024ULL)
        snprintf(out, out_size, "%.1f KB", (double)size / 1024.0);
    else
        snprintf(out, out_size, "%llu B", (unsigned long long)size);
}

static const char* extension_of(const char* name)
{
    const char* dot = strrchr(name ? name : "", '.');
    return dot ? dot : "";
}

static int ext_equals(const char* name, const char* ext)
{
    const char* p = extension_of(name);
    while (*p && *ext) {
        if (tolower((unsigned char)*p) != tolower((unsigned char)*ext))
            return 0;
        p++;
        ext++;
    }
    return *p == '\0' && *ext == '\0';
}

static const char* file_category(const char* name)
{
    if (ext_equals(name, ".jpg") || ext_equals(name, ".jpeg") ||
        ext_equals(name, ".png") || ext_equals(name, ".bmp") ||
        ext_equals(name, ".gif"))
        return "PHOTO";

    if (ext_equals(name, ".mp3") || ext_equals(name, ".wav") ||
        ext_equals(name, ".at3") || ext_equals(name, ".oma") ||
        ext_equals(name, ".m4a") || ext_equals(name, ".aac"))
        return "MUSIC";

    if (ext_equals(name, ".iso") || ext_equals(name, ".cso") ||
        ext_equals(name, ".zso") || ext_equals(name, ".pbp"))
        return "GAME";

    return "FILE";
}

static const char* file_category_display(const char* category)
{
    if (!category)
        return ui_text("Arquivo", "File");

    if (!strcmp(category, "PHOTO"))
        return ui_text("Foto", "Photo");
    if (!strcmp(category, "MUSIC"))
        return ui_text("Musica", "Music");
    if (!strcmp(category, "GAME"))
        return ui_text("Jogo", "Game");

    /* Compatibilidade visual com builds antigos durante testes. */
    if (!strcmp(category, "Foto"))
        return ui_text("Foto", "Photo");
    if (!strcmp(category, "Musica"))
        return ui_text("Musica", "Music");
    if (!strcmp(category, "Jogo"))
        return ui_text("Jogo", "Game");

    return ui_text("Arquivo", "File");
}

static const char* base_name(const char* path)
{
    const char* slash;
    if (!path)
        return "arquivo.bin";

    slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static void sanitize_filename(const char* input, char* output, int output_size)
{
    int i, j = 0;
    const char* b = base_name(input);

    if (!output || output_size <= 0)
        return;

    for (i = 0; b[i] && j < output_size - 1; ++i) {
        unsigned char c = (unsigned char)b[i];
        if (c == '/' || c == '\\' || c == ':' || c < 32)
            output[j++] = '_';
        else
            output[j++] = (char)c;
    }

    output[j] = '\0';
    if (j == 0)
        safe_copy(output, "arquivo.bin", output_size);
}

static int path_exists(const char* path)
{
    SceIoStat st;
    memset(&st, 0, sizeof(st));
    return sceIoGetstat(path, &st) >= 0;
}

static int directory_exists(const char* path)
{
    SceUID d = sceIoDopen(path);
    if (d >= 0) {
        sceIoDclose(d);
        return 1;
    }
    return 0;
}

static void ensure_directory_recursive(const char* dir)
{
    char temp[512];
    int i;

    safe_copy(temp, dir, sizeof(temp));

    /* pula "ms0:/" ou "ef0:/" */
    for (i = 5; temp[i]; ++i) {
        if (temp[i] == '/') {
            char old = temp[i];
            temp[i] = '\0';
            sceIoMkdir(temp, 0777);
            temp[i] = old;
        }
    }

    sceIoMkdir(temp, 0777);
}

static void join_path(const char* dir, const char* name, char* out, int out_size)
{
    size_t len;

    if (!out || out_size <= 0)
        return;

    out[0] = '\0';
    safe_copy(out, dir ? dir : "", out_size);
    len = strlen(out);

    if (len > 0 && out[len - 1] != '/')
        safe_append(out, "/", out_size);

    safe_append(out, name ? name : "", out_size);
}

static void make_unique_path(const char* dir, const char* filename, char* out, int out_size)
{
    char safe[192];
    char stem[160];
    char ext[32];
    char candidate[224];
    const char* dot;
    int n;

    sanitize_filename(filename, safe, sizeof(safe));
    dot = strrchr(safe, '.');

    if (dot) {
        int stem_len = (int)(dot - safe);
        if (stem_len >= (int)sizeof(stem))
            stem_len = (int)sizeof(stem) - 1;
        memcpy(stem, safe, (size_t)stem_len);
        stem[stem_len] = '\0';
        safe_copy(ext, dot, sizeof(ext));
    } else {
        safe_copy(stem, safe, sizeof(stem));
        ext[0] = '\0';
    }

    join_path(dir, safe, out, out_size);
    if (!path_exists(out))
        return;

    for (n = 1; n < 1000; ++n) {
        snprintf(candidate, sizeof(candidate), "%.150s_%d%.31s", stem, n, ext);
        join_path(dir, candidate, out, out_size);
        if (!path_exists(out))
            return;
    }

    /* Fallback deterministico caso existam 999 colisoes. */
    snprintf(candidate, sizeof(candidate), "ADShare_%08X%.31s",
             (unsigned int)now_us(), ext);
    join_path(dir, candidate, out, out_size);
}

static void choose_receive_path(const char* filename, char* final_path, int final_size)
{
    const char* storage = directory_exists("ms0:/") ? "ms0:" : "ef0:";
    char dir[256];

    final_path[0] = '\0';

    if (ext_equals(filename, ".jpg") || ext_equals(filename, ".jpeg") ||
        ext_equals(filename, ".png") || ext_equals(filename, ".bmp") ||
        ext_equals(filename, ".gif")) {
        snprintf(dir, sizeof(dir), "%s/PICTURE/ADShare", storage);
        ensure_directory_recursive(dir);
        make_unique_path(dir, filename, final_path, final_size);
        return;
    }

    if (ext_equals(filename, ".mp3") || ext_equals(filename, ".wav") ||
        ext_equals(filename, ".at3") || ext_equals(filename, ".oma") ||
        ext_equals(filename, ".m4a") || ext_equals(filename, ".aac")) {
        snprintf(dir, sizeof(dir), "%s/MUSIC/ADShare", storage);
        ensure_directory_recursive(dir);
        make_unique_path(dir, filename, final_path, final_size);
        return;
    }

    if (ext_equals(filename, ".iso") || ext_equals(filename, ".cso") ||
        ext_equals(filename, ".zso")) {
        snprintf(dir, sizeof(dir), "%s/ISO", storage);
        ensure_directory_recursive(dir);
        make_unique_path(dir, filename, final_path, final_size);
        return;
    }

    if (ext_equals(filename, ".pbp")) {
        int n;

        /* PBP executavel precisa se chamar EBOOT.PBP dentro de uma pasta. */
        for (n = 0; n < 1000; ++n) {
            if (n == 0)
                snprintf(dir, sizeof(dir), "%s/PSP/GAME/ADShare", storage);
            else
                snprintf(dir, sizeof(dir), "%s/PSP/GAME/ADShare%03d", storage, n);

            join_path(dir, "EBOOT.PBP", final_path, final_size);
            if (!path_exists(final_path)) {
                ensure_directory_recursive(dir);
                return;
            }
        }
    }

    snprintf(dir, sizeof(dir), "%s/ADShare", storage);
    ensure_directory_recursive(dir);
    make_unique_path(dir, filename, final_path, final_size);
}

/* =========================================================
   DEVICE INFO - KERNEL / IDSTORAGE
   ========================================================= */

/*
 * O código abaixo evita APIs antigas de SystemControl que variam entre CFWs.
 *
 * - kuKernelGetModel(): geração real do PSP em user mode.
 * - LibPspExploit: executa adshare_kernel_probe() em contexto kernel.
 * - pspXploitFindFunction(): resolve apenas exports existentes no firmware.
 *
 * NIDs usados:
 *   sceIdStorageLookup           0x6FE062D1
 *   sceSysregGetTachyonVersion  0xE2A5D1EE
 *   sceSysconGetBaryonVersion   0x7EC5A957
 *   sceSysconGetPommelVersion   0xE7E87741
 *
 * A leitura da região usa IDStorage leaf 0x0100, offset 0xF5,
 * mesma técnica pública usada pelo pspIdent.
 */

#define NID_IDSTORAGE_LOOKUP     0x6FE062D1
#define NID_SYSREG_GET_TACHYON  0xE2A5D1EE
#define NID_SYSCON_GET_BARYON   0x7EC5A957
#define NID_SYSCON_GET_POMMEL   0xE7E87741

typedef int (*IdStorageLookupFn)(int key, int offset, void* buffer, int length);
typedef int (*SysregGetTachyonFn)(void);
typedef int (*SysconGetVersionFn)(int* version);

typedef struct HardwareProbeResult {
    volatile int completed;
    volatile int any_success;

    volatile int region_valid;
    volatile uint8_t region_id;

    volatile int tachyon_valid;
    volatile int baryon_valid;
    volatile int pommel_valid;

    volatile uint32_t tachyon;
    volatile uint32_t baryon;
    volatile uint32_t pommel;
} HardwareProbeResult;

static volatile HardwareProbeResult g_hwprobe;
static int g_hwprobe_attempted = 0;
static int g_hwprobe_status = -1;

/*
 * Tabela usada por pspIdent para transformar o byte de região do IDStorage
 * no sufixo comercial. Ex.: região 0x04 => sufixo 1 => PSP-3001.
 */
static const int g_model_region_suffix[16] = {
    0, 0, 0, 0, 1, 4, 5, 3, 10, 2, 6, 7, 8, 9, 0, 0
};

static const char* language_name(int lang)
{
    switch (lang) {
        case PSP_SYSTEMPARAM_LANGUAGE_JAPANESE:
            return ui_text("Japones", "Japanese");
        case PSP_SYSTEMPARAM_LANGUAGE_ENGLISH:
            return ui_text("Ingles", "English");
        case PSP_SYSTEMPARAM_LANGUAGE_FRENCH:
            return ui_text("Frances", "French");
        case PSP_SYSTEMPARAM_LANGUAGE_SPANISH:
            return ui_text("Espanhol", "Spanish");
        case PSP_SYSTEMPARAM_LANGUAGE_GERMAN:
            return ui_text("Alemao", "German");
        case PSP_SYSTEMPARAM_LANGUAGE_ITALIAN:
            return ui_text("Italiano", "Italian");
        case PSP_SYSTEMPARAM_LANGUAGE_DUTCH:
            return ui_text("Holandes", "Dutch");
        case PSP_SYSTEMPARAM_LANGUAGE_PORTUGUESE:
            return ui_text("Portugues", "Portuguese");
        case PSP_SYSTEMPARAM_LANGUAGE_RUSSIAN:
            return ui_text("Russo", "Russian");
        case PSP_SYSTEMPARAM_LANGUAGE_KOREAN:
            return ui_text("Coreano", "Korean");
        case PSP_SYSTEMPARAM_LANGUAGE_CHINESE_TRADITIONAL:
            return ui_text("Chines Trad.", "Chinese Trad.");
        case PSP_SYSTEMPARAM_LANGUAGE_CHINESE_SIMPLIFIED:
            return ui_text("Chines Simpl.", "Chinese Simpl.");
        default:
            return ui_text("Desconhecido", "Unknown");
    }
}

static void firmware_string(char* out, int out_size)
{
    unsigned int v = (unsigned int)sceKernelDevkitVersion();
    unsigned int major = (v >> 24) & 0xFF;
    unsigned int minor = (v >> 16) & 0xFF;
    unsigned int rev = (v >> 8) & 0xFF;

    if (rev == 0)
        snprintf(out, out_size, "%u.%02u", major, minor);
    else
        snprintf(out, out_size, "%u.%02u.%u", major, minor, rev);
}

static const char* region_name_from_id(uint8_t id)
{
    switch (id) {
        case 0x03: return ui_text("Japao", "Japan");
        case 0x04: return ui_text("America do Norte", "North America");
        case 0x05: return ui_text("Europa / Oriente Medio / Africa",
                                  "Europe / Middle East / Africa");
        case 0x06: return ui_text("Coreia", "Korea");
        case 0x07: return ui_text("Reino Unido", "United Kingdom");
        case 0x08: return ui_text("America Latina", "Latin America");
        case 0x09: return ui_text("Australia / Nova Zelandia",
                                  "Australia / New Zealand");
        case 0x0A: return "Hong Kong";
        case 0x0B: return "Taiwan";
        case 0x0C: return ui_text("Russia", "Russia");
        case 0x0D: return ui_text("China", "China");
        case 0x0E: return ui_text("AV / Teste", "AV / Test");
        default:   return ui_text("Desconhecida", "Unknown");
    }
}

static void generation_name(int gen, char* out, int out_size)
{
    if (gen >= 0 && gen <= 15)
        snprintf(out, out_size, "%02dg", gen + 1);
    else
        safe_copy(out, ui_text("Desconhecida", "Unknown"), out_size);
}

static int commercial_suffix_from_region(uint8_t region_id)
{
    if (region_id < 16)
        return g_model_region_suffix[region_id];

    return 0;
}

/*
 * Executada com privilégio kernel por pspXploitExecuteKernel().
 * Mantém a rotina curta: resolve quatro funções, lê os IDs e retorna.
 */
static void adshare_kernel_probe(void)
{
    int old_k1;
    int old_userlevel;
    const char* sysreg_module;

    IdStorageLookupFn idstorage_lookup = NULL;
    SysregGetTachyonFn get_tachyon = NULL;
    SysconGetVersionFn get_baryon = NULL;
    SysconGetVersionFn get_pommel = NULL;

    uint32_t address;
    int temp;
    uint8_t region_byte;

    old_k1 = pspSdkSetK1(0);
    old_userlevel = pspXploitSetUserLevel(8);

    /*
     * O próprio LibPspExploit recomenda reparar o kernel antes de resolver
     * exports após o exploit. É a mesma sequência usada pelo pspIdent.
     */
    pspXploitRepairKernel();

    sysreg_module =
        (pspXploitFindTextAddrByName("sceLowIO_Driver") == 0)
        ? "sceSYSREG_Driver"
        : "sceLowIO_Driver";

    address = pspXploitFindFunction(
        "sceIdStorage_Service",
        "sceIdStorage_driver",
        NID_IDSTORAGE_LOOKUP
    );
    if (address)
        idstorage_lookup = (IdStorageLookupFn)(uintptr_t)address;

    address = pspXploitFindFunction(
        sysreg_module,
        "sceSysreg_driver",
        NID_SYSREG_GET_TACHYON
    );
    if (address)
        get_tachyon = (SysregGetTachyonFn)(uintptr_t)address;

    address = pspXploitFindFunction(
        "sceSYSCON_Driver",
        "sceSyscon_driver",
        NID_SYSCON_GET_BARYON
    );
    if (address)
        get_baryon = (SysconGetVersionFn)(uintptr_t)address;

    address = pspXploitFindFunction(
        "sceSYSCON_Driver",
        "sceSyscon_driver",
        NID_SYSCON_GET_POMMEL
    );
    if (address)
        get_pommel = (SysconGetVersionFn)(uintptr_t)address;

    if (idstorage_lookup) {
        region_byte = 0xFF;
        if (idstorage_lookup(0x0100, 0xF5, &region_byte, 1) >= 0) {
            g_hwprobe.region_id = region_byte;
            g_hwprobe.region_valid = 1;
            g_hwprobe.any_success = 1;
        }
    }

    if (get_tachyon) {
        temp = get_tachyon();
        if (temp >= 0) {
            g_hwprobe.tachyon = (uint32_t)temp;
            g_hwprobe.tachyon_valid = 1;
            g_hwprobe.any_success = 1;
        }
    }

    if (get_baryon) {
        temp = 0;
        if (get_baryon(&temp) >= 0) {
            g_hwprobe.baryon = (uint32_t)temp;
            g_hwprobe.baryon_valid = 1;
            g_hwprobe.any_success = 1;
        }
    }

    if (get_pommel) {
        temp = 0;
        if (get_pommel(&temp) >= 0) {
            g_hwprobe.pommel = (uint32_t)temp;
            g_hwprobe.pommel_valid = 1;
            g_hwprobe.any_success = 1;
        }
    }

    g_hwprobe.completed = 1;

    pspXploitSetUserLevel(old_userlevel);
    pspSdkSetK1(old_k1);
}

/*
 * Faz a elevação apenas uma vez por execução do ADShare.
 * collect_device_info() pode ser chamado muitas vezes pela interface.
 */
static int probe_hardware_once(void)
{
    int ret;

    if (g_hwprobe_attempted)
        return g_hwprobe_status;

    g_hwprobe_attempted = 1;
    memset((void*)&g_hwprobe, 0, sizeof(g_hwprobe));

    ret = pspXploitInitKernelExploit();
    if (ret != 0) {
        g_hwprobe_status = ret;
        return ret;
    }

    ret = pspXploitDoKernelExploit();
    if (ret != 0) {
        g_hwprobe_status = ret;
        return ret;
    }

    pspXploitExecuteKernel(adshare_kernel_probe);

    if (!g_hwprobe.completed || !g_hwprobe.any_success) {
        g_hwprobe_status = -1;
        return -1;
    }

    g_hwprobe_status = 0;
    return 0;
}

/*
 * Retorna um nome de placa somente quando Tachyon/Baryon/Pommel permitem
 * uma conclusão útil. Mapeamento adaptado da tabela pública do pspIdent.
 */
static void board_from_real_ids(
    int tachyon_valid, uint32_t tachyon,
    int baryon_valid, uint32_t baryon,
    int pommel_valid, uint32_t pommel,
    char* out, int out_size)
{
    if (!tachyon_valid) {
        safe_copy(out, "Tachyon indisponivel", out_size);
        return;
    }

    switch (tachyon) {
        case 0x00140000:
            if (baryon_valid) {
                if (baryon == 0x00010600) { safe_copy(out, "TA-079v1", out_size); return; }
                if (baryon == 0x00020600) { safe_copy(out, "TA-079v2", out_size); return; }
                if (baryon == 0x00030600) { safe_copy(out, "TA-079v3", out_size); return; }
            }
            safe_copy(out, ui_text("Familia TA-079", "TA-079 family"), out_size);
            return;

        case 0x00200000:
            if (baryon_valid) {
                if (baryon == 0x00030600) { safe_copy(out, "TA-079v4", out_size); return; }
                if (baryon == 0x00040600) { safe_copy(out, "TA-079v5", out_size); return; }
            }
            safe_copy(out, ui_text("Familia TA-079", "TA-079 family"), out_size);
            return;

        case 0x00300000:
            if (pommel_valid) {
                if (pommel == 0x00000103) { safe_copy(out, "TA-081v1", out_size); return; }
                if (pommel == 0x00000104) { safe_copy(out, "TA-081v2", out_size); return; }
            }
            safe_copy(out, ui_text("Familia TA-081", "TA-081 family"), out_size);
            return;

        case 0x00400000:
            if (baryon_valid) {
                if (baryon == 0x00114000) { safe_copy(out, "TA-082", out_size); return; }
                if (baryon == 0x00121000) { safe_copy(out, "TA-086", out_size); return; }
            }
            safe_copy(out, "TA-082 / TA-086", out_size);
            return;

        case 0x00500000:
            if (baryon_valid) {
                if (baryon == 0x0022B200) { safe_copy(out, "TA-085v1", out_size); return; }
                if (baryon == 0x00234000) { safe_copy(out, "TA-085v2", out_size); return; }

                if (baryon == 0x00243000 && pommel_valid) {
                    if (pommel == 0x00000123) {
                        safe_copy(out, "TA-088v1/v2", out_size);
                        return;
                    }
                    if (pommel == 0x00000132) {
                        safe_copy(out, "TA-090v1", out_size);
                        return;
                    }
                }
            }
            safe_copy(out, "TA-085 / TA-088 / TA-090", out_size);
            return;

        case 0x00600000:
            if (baryon_valid) {
                if (baryon == 0x00234000) {
                    safe_copy(out, "TA-088v3 / TA-085v2 hybrid", out_size);
                    return;
                }
                if (baryon == 0x00243000) {
                    safe_copy(out, "TA-088v3", out_size);
                    return;
                }
                if (baryon == 0x00263100) {
                    if (pommel_valid && pommel == 0x00000132) {
                        safe_copy(out, "TA-090v2", out_size);
                        return;
                    }
                    if (pommel_valid && pommel == 0x00000133) {
                        safe_copy(out, "TA-090v3", out_size);
                        return;
                    }
                    safe_copy(out, "TA-090v2/v3", out_size);
                    return;
                }
                if (baryon == 0x00285000) {
                    safe_copy(out, "TA-092", out_size);
                    return;
                }
            }
            safe_copy(out, "TA-088 / TA-090 / TA-092", out_size);
            return;

        case 0x00720000:
            safe_copy(out, "TA-091", out_size);
            return;

        case 0x00810000:
            if (baryon_valid) {
                if (baryon == 0x002C4000) {
                    if (pommel_valid && pommel == 0x00000141) {
                        safe_copy(out, "TA-093v1", out_size);
                        return;
                    }
                    if (pommel_valid && pommel == 0x00000143) {
                        safe_copy(out, "TA-093v2", out_size);
                        return;
                    }
                    safe_copy(out, "TA-093", out_size);
                    return;
                }
                if (baryon == 0x002E4000) {
                    safe_copy(out, "TA-095v1 (09g)", out_size);
                    return;
                }
                if (baryon == 0x012E4000) {
                    safe_copy(out, "TA-095v3 (07g)", out_size);
                    return;
                }
                if (baryon == 0x00323100) {
                    safe_copy(out, "TA-094 v1 (PSP Go)", out_size);
                    return;
                }
                if (baryon == 0x00324000) {
                    safe_copy(out, "TA-094 v2 (PSP Go)", out_size);
                    return;
                }
            }
            safe_copy(out, "TA-093 / TA-094 / TA-095", out_size);
            return;

        case 0x00820000:
            if (baryon_valid) {
                if (baryon == 0x002E4000) {
                    safe_copy(out, "TA-095v2 (09g)", out_size);
                    return;
                }
                if (baryon == 0x012E4000) {
                    safe_copy(out, "TA-095v4 (07g)", out_size);
                    return;
                }
            }
            safe_copy(out, ui_text("Familia TA-095", "TA-095 family"), out_size);
            return;

        case 0x00900000:
            safe_copy(out, "TA-096 / TA-097 (PSP Street)", out_size);
            return;

        default:
            snprintf(out, out_size, "%s (Tachyon 0x%08X)",
                     ui_text("Desconhecida", "Unknown"),
                     (unsigned int)tachyon);
            return;
    }
}

static void build_model_name(
    int generation,
    int region_valid,
    uint8_t region_id,
    char* out,
    int out_size)
{
    int suffix = region_valid ? commercial_suffix_from_region(region_id) : 0;

    /*
     * kuKernelGetModel() retorna 0 para 01g, 1 para 02g, 2 para 03g etc.
     * Quando o sufixo regional nao esta disponivel, nao inventamos um SKU.
     */
    switch (generation) {
        case 0:
            if (suffix > 0) snprintf(out, out_size, "PSP-10%02d", suffix);
            else safe_copy(out, "PSP-1000 series", out_size);
            break;

        case 1:
            if (suffix > 0) snprintf(out, out_size, "PSP-20%02d", suffix);
            else safe_copy(out, "PSP-2000 series", out_size);
            break;

        case 2: /* 03g */
        case 3: /* 04g */
        case 6: /* 07g */
        case 8: /* 09g */
            if (suffix > 0) snprintf(out, out_size, "PSP-30%02d", suffix);
            else safe_copy(out, "PSP-3000 series", out_size);
            break;

        case 4: /* 05g */
            if (suffix > 0) snprintf(out, out_size, "PSP-N10%02d", suffix);
            else safe_copy(out, "PSP Go / N1000 series", out_size);
            break;

        case 10: /* 11g */
            if (suffix > 0) snprintf(out, out_size, "PSP-E10%02d", suffix);
            else safe_copy(out, "PSP Street / E1000 series", out_size);
            break;

        default:
            snprintf(out, out_size, "PSP geracao %02dg", generation + 1);
            break;
    }
}

static void collect_device_info(void)
{
    int lang = -1;
    int configured_channel = 0;
    char mac[32];
    int generation;
    int probe_ret;

    memset(&g_device, 0, sizeof(g_device));

    if (sceUtilityGetSystemParamString(
            PSP_SYSTEMPARAM_ID_STRING_NICKNAME,
            g_device.nickname,
            sizeof(g_device.nickname)) < 0) {
        safe_copy(g_device.nickname, "PSP", sizeof(g_device.nickname));
    }

    safe_copy(g_local_nickname, g_device.nickname, sizeof(g_local_nickname));
    firmware_string(g_device.firmware, sizeof(g_device.firmware));

    sceUtilityGetSystemParamInt(PSP_SYSTEMPARAM_ID_INT_LANGUAGE, &lang);
    sceUtilityGetSystemParamInt(
        PSP_SYSTEMPARAM_ID_INT_ADHOC_CHANNEL,
        &configured_channel
    );

    safe_copy(g_device.language, language_name(lang), sizeof(g_device.language));

    if (configured_channel == PSP_SYSTEMPARAM_ADHOC_CHANNEL_AUTOMATIC)
        safe_copy(g_device.adhoc_channel,
                  ui_text("Automatico", "Automatic"),
                  sizeof(g_device.adhoc_channel));
    else
        snprintf(g_device.adhoc_channel, sizeof(g_device.adhoc_channel),
                 "%s %d", ui_text("Canal", "Channel"), configured_channel);

    if (sceWlanGetEtherAddr(g_local_mac) >= 0) {
        mac_to_string(g_local_mac, mac, sizeof(mac));
        safe_copy(g_device.mac, mac, sizeof(g_device.mac));
    } else {
        safe_copy(g_device.mac, ui_text("Indisponivel", "Unavailable"), sizeof(g_device.mac));
    }

    /*
     * Fonte primária do modelo: KUBridge. Não existe mais heurística por RAM.
     */
    generation = kuKernelGetModel();
    g_device.kernel_model_result = generation;
    g_device.model_generation = generation;
    generation_name(generation, g_device.generation,
                    sizeof(g_device.generation));

    /*
     * Fonte dos IDs físicos: rotina em kernel via LibPspExploit.
     * O resultado fica em cache para não repetir a elevação de privilégio.
     */
    probe_ret = probe_hardware_once();

    if (g_hwprobe.region_valid) {
        g_device.region_valid = 1;
        g_device.region_id = g_hwprobe.region_id;

        safe_copy(g_device.region,
                  region_name_from_id(g_device.region_id),
                  sizeof(g_device.region));

        snprintf(g_device.region_id_text,
                 sizeof(g_device.region_id_text),
                 "0x%02X -> %s %d",
                 (unsigned int)g_device.region_id,
                 ui_text("sufixo", "suffix"),
                 commercial_suffix_from_region(g_device.region_id));
    } else {
        safe_copy(g_device.region, ui_text("IDStorage indisponivel", "IDStorage unavailable"),
                  sizeof(g_device.region));
        safe_copy(g_device.region_id_text, ui_text("Indisponivel", "Unavailable"),
                  sizeof(g_device.region_id_text));
    }

    build_model_name(
        generation,
        g_device.region_valid,
        g_device.region_id,
        g_device.model,
        sizeof(g_device.model)
    );

    if (g_hwprobe.tachyon_valid) {
        g_device.tachyon_valid = 1;
        g_device.tachyon = g_hwprobe.tachyon;
        snprintf(g_device.tachyon_text, sizeof(g_device.tachyon_text),
                 "0x%08X", (unsigned int)g_device.tachyon);
    } else {
        safe_copy(g_device.tachyon_text, ui_text("Indisponivel", "Unavailable"),
                  sizeof(g_device.tachyon_text));
    }

    if (g_hwprobe.baryon_valid) {
        g_device.baryon_valid = 1;
        g_device.baryon = g_hwprobe.baryon;
        snprintf(g_device.baryon_text, sizeof(g_device.baryon_text),
                 "0x%08X", (unsigned int)g_device.baryon);
    } else {
        safe_copy(g_device.baryon_text, ui_text("Indisponivel", "Unavailable"),
                  sizeof(g_device.baryon_text));
    }

    if (g_hwprobe.pommel_valid) {
        g_device.pommel_valid = 1;
        g_device.pommel = g_hwprobe.pommel;
        snprintf(g_device.pommel_text, sizeof(g_device.pommel_text),
                 "0x%08X", (unsigned int)g_device.pommel);
    } else {
        safe_copy(g_device.pommel_text, ui_text("Indisponivel", "Unavailable"),
                  sizeof(g_device.pommel_text));
    }

    board_from_real_ids(
        g_device.tachyon_valid, g_device.tachyon,
        g_device.baryon_valid, g_device.baryon,
        g_device.pommel_valid, g_device.pommel,
        g_device.board_family, sizeof(g_device.board_family)
    );

    if (probe_ret == 0) {
        safe_copy(g_device.kernel_source,
                  "KUBridge + LibPspExploit + IDStorage",
                  sizeof(g_device.kernel_source));
        safe_copy(g_device.probe_status_text,
                  ui_text("Hardware lido em kernel", "Hardware read in kernel"),
                  sizeof(g_device.probe_status_text));
    } else {
        safe_copy(g_device.kernel_source,
                  ui_text("KUBridge (IDs kernel indisponiveis)", "KUBridge (kernel IDs unavailable)"),
                  sizeof(g_device.kernel_source));
        snprintf(g_device.probe_status_text,
                 sizeof(g_device.probe_status_text),
                 "Probe kernel: 0x%08X",
                 (unsigned int)probe_ret);
    }
}


/* =========================================================
   UI HELPERS
   ========================================================= */

static int text_width(const char* text)
{
    if (!text)
        return 0;
    return g_font ? oslGetStringWidth(text) : (int)strlen(text) * 8;
}

static int center_x(const char* text)
{
    return (480 - text_width(text)) / 2;
}

static void fit_text(const char* src, char* dst, int dst_size, int max_width)
{
    int len;
    char test[320];

    safe_copy(dst, src, dst_size);
    if (text_width(dst) <= max_width)
        return;

    len = strlen(dst);
    while (len > 3) {
        dst[--len] = '\0';
        snprintf(test, sizeof(test), "%s...", dst);
        if (text_width(test) <= max_width) {
            safe_copy(dst, test, dst_size);
            return;
        }
    }
}

static void draw_background(void)
{
    oslDrawFillRect(0, 0, 480, 272, C_BG);
    oslDrawFillRect(0, 0, 480, 24, C_BAR_BG);
    oslDrawFillRect(0, 24, 480, 25, C_PSN_BLUE);
    oslDrawFillRect(0, 248, 480, 249, RGBA(45, 45, 50, 255));
    oslDrawFillRect(0, 249, 480, 272, C_BAR_BG);
}

static void draw_header(const char* title, const char* right)
{
    oslSetBkColor(RGBA(0, 0, 0, 0));
    oslSetTextColor(C_TEXT);
    oslDrawString(14, 6, title ? title : APP_NAME);

    if (right && right[0]) {
        int x = 466 - text_width(right);
        if (x < 250) x = 250;
        oslSetTextColor(C_TEXT_DIM);
        oslDrawString(x, 6, right);
    }
}

static void draw_footer(const char* text)
{
    oslSetTextColor(C_TEXT_DIM);
    oslDrawString(center_x(text), 255, text);
}

static void draw_panel(int x1, int y1, int x2, int y2, unsigned int border)
{
    oslDrawFillRect(x1, y1, x2, y2, C_PANEL);
    oslDrawRect(x1, y1, x2, y2, border);
}

static void draw_psp_icon(int x, int y, unsigned int color)
{
    oslDrawFillRect(x + 2, y + 5, x + 28, y + 21, color);
    oslDrawRect(x + 5, y + 8, x + 25, y + 18, C_TEXT_DIM);
    oslDrawFillRect(x + 0, y + 10, x + 4, y + 16, color);
    oslDrawFillRect(x + 28, y + 10, x + 32, y + 16, color);
    oslDrawFillRect(x + 8, y + 24, x + 22, y + 26, C_TEXT_DARK);
}

static void draw_file_icon(int x, int y, const char* category, int selected)
{
    unsigned int c = selected ? C_PSN_BLUE : RGBA(58, 58, 66, 255);

    if (!strcmp(category, "PHOTO") || !strcmp(category, "Foto")) {
        oslDrawFillRect(x + 3, y + 4, x + 27, y + 24, c);
        oslDrawRect(x + 6, y + 7, x + 24, y + 21, C_TEXT_DIM);
        oslDrawFillRect(x + 17, y + 10, x + 20, y + 13, C_TEXT);
    } else if (!strcmp(category, "MUSIC") || !strcmp(category, "Musica")) {
        oslDrawFillRect(x + 18, y + 4, x + 21, y + 20, c);
        oslDrawFillRect(x + 21, y + 4, x + 27, y + 7, c);
        oslDrawFillRect(x + 10, y + 17, x + 19, y + 25, c);
    } else if (!strcmp(category, "GAME") || !strcmp(category, "Jogo")) {
        oslDrawFillRect(x + 3, y + 8, x + 29, y + 22, c);
        oslDrawFillRect(x + 7, y + 4, x + 25, y + 10, c);
        oslDrawFillRect(x + 8, y + 13, x + 15, y + 15, C_TEXT);
        oslDrawFillRect(x + 10, y + 11, x + 12, y + 17, C_TEXT);
    } else {
        oslDrawFillRect(x + 6, y + 3, x + 25, y + 25, c);
        oslDrawRect(x + 9, y + 8, x + 22, y + 9, C_TEXT_DIM);
        oslDrawRect(x + 9, y + 13, x + 22, y + 14, C_TEXT_DIM);
    }
}

static void draw_folder_icon(int x, int y, int selected)
{
    unsigned int mainc = selected ? C_PSN_BLUE : C_FOLDER;
    unsigned int tabc = selected ? C_PSN_BLUE : C_FOLDER_DARK;
    oslDrawFillRect(x + 2, y + 9, x + 29, y + 25, mainc);
    oslDrawFillRect(x + 2, y + 5, x + 15, y + 10, tabc);
}

static void draw_loading(const char* title, const char* message)
{
    oslStartDrawing();
    draw_background();
    draw_header(APP_NAME, title);
    draw_panel(35, 92, 445, 164, C_PSN_BLUE);
    oslSetTextColor(C_TEXT);
    oslDrawString(center_x(message), 116, message);
    oslSetTextColor(C_TEXT_DIM);
    oslDrawString(center_x(ui_text("Nao desligue o PSP", "Do not turn off the PSP")), 141,
                  ui_text("Nao desligue o PSP", "Do not turn off the PSP"));
    oslEndDrawing();
    oslSyncFrame();
}

static void show_message(const char* right, const char* title, const char* line1, const char* line2, unsigned int border)
{
    while (!osl_quit) {
        oslStartDrawing();
        draw_background();
        draw_header(APP_NAME, right);
        draw_panel(28, 72, 452, 196, border);

        oslSetTextColor(C_TEXT);
        oslDrawString(center_x(title), 92, title);
        oslSetTextColor(C_TEXT_DIM);
        oslDrawString(center_x(line1 ? line1 : ""), 126, line1 ? line1 : "");
        if (line2 && line2[0])
            oslDrawString(center_x(line2), 147, line2);

        draw_footer(ui_text("[O] Voltar", "[O] Back"));
        oslEndDrawing();
        oslSyncFrame();

        oslReadKeys();
        if (osl_keys->pressed.circle || osl_keys->pressed.cross)
            break;
    }
}

/* =========================================================
   AD HOC INIT / SHUTDOWN
   ========================================================= */

static void stop_adhoc(void);

static int wait_adhoc_connected(int timeout_ms)
{
    int elapsed = 0;
    int state = 0;

    while (elapsed < timeout_ms) {
        int ret = sceNetAdhocctlGetState(&state);
        if (ret >= 0 && state == 1)
            return 1;

        draw_loading("Ad Hoc", ui_text("Entrando no grupo ADShare...", "Joining ADShare group..."));
        sceKernelDelayThread(100000);
        elapsed += 100;
    }

    return 0;
}

static int start_adhoc(void)
{
    int ret;
    struct productStruct product;
    struct SceNetAdhocctlParams params;

    if (g_adhoc_connected && g_pdp_id >= 0)
        return 1;

    if (!sceWlanGetSwitchState()) {
        show_message(ui_text("Erro", "Error"),
                     ui_text("WLAN desligada", "WLAN is off"),
                     ui_text("Ative a chave WLAN do PSP.", "Turn on the PSP WLAN switch."),
                     ui_text("Depois tente novamente.", "Then try again."), C_ERROR);
        return 0;
    }

    /* Mantem o clock padrao seguro para WLAN e reduz consumo desnecessario. */
    scePowerSetClockFrequency(222, 222, 111);

    draw_loading("Ad Hoc", ui_text("Carregando modulos de rede...", "Loading network modules..."));

    ret = sceUtilityLoadNetModule(PSP_NET_MODULE_COMMON);
    if (ret < 0 && ret != (int)0x80111102) {
        char msg[96];
        snprintf(msg, sizeof(msg), "COMMON: 0x%08X", (unsigned int)ret);
        show_message(ui_text("Erro", "Error"), ui_text("Falha na rede", "Network failure"), msg, "", C_ERROR);
        return 0;
    }

    ret = sceUtilityLoadNetModule(PSP_NET_MODULE_ADHOC);
    if (ret < 0 && ret != (int)0x80111102) {
        char msg[96];
        snprintf(msg, sizeof(msg), "ADHOC: 0x%08X", (unsigned int)ret);
        show_message(ui_text("Erro", "Error"), ui_text("Falha no modulo Ad Hoc", "Ad Hoc module failure"), msg, "", C_ERROR);
        return 0;
    }

    ret = sceNetInit(128 * 1024, 42, 4 * 1024, 42, 4 * 1024);
    if (ret < 0) {
        char msg[96];
        snprintf(msg, sizeof(msg), "sceNetInit: 0x%08X", (unsigned int)ret);
        show_message(ui_text("Erro", "Error"), ui_text("Falha ao iniciar rede", "Failed to initialize network"), msg, "", C_ERROR);
        return 0;
    }
    g_net_initialized = 1;

    ret = sceNetAdhocInit();
    if (ret < 0) {
        char msg[96];
        snprintf(msg, sizeof(msg), "sceNetAdhocInit: 0x%08X", (unsigned int)ret);
        stop_adhoc();
        show_message(ui_text("Erro", "Error"), ui_text("Falha no Ad Hoc", "Ad Hoc failure"), msg, "", C_ERROR);
        return 0;
    }
    g_adhoc_initialized = 1;

    /*
     * productStruct.product possui EXATAMENTE 9 bytes.
     * Em PSP real, um Product ID curto (ex.: 8 chars + '\0') faz
     * sceNetAdhocctlInit() retornar 0x80410B04 (INVALID_ARG).
     *
     * Portanto NÃO use strcpy/safe_copy aqui. Copiamos os 9 bytes
     * diretamente, sem terminador NUL dentro de product.product.
     */
    memset(&product, 0, sizeof(product));
    product.unknown = 0;
    memcpy(product.product, ADHOC_PRODUCT, sizeof(product.product));

    ret = sceNetAdhocctlInit(0x2000, 0x30, &product);
    if (ret < 0) {
        char msg[128];

        if ((unsigned int)ret == 0x80410B04u) {
            snprintf(msg, sizeof(msg),
                     "adhocctlInit: 0x%08X (Product ID invalid)",
                     (unsigned int)ret);
        } else if ((unsigned int)ret == 0x80410B03u) {
            snprintf(msg, sizeof(msg),
                     "adhocctlInit: 0x%08X (WLAN off)",
                     (unsigned int)ret);
        } else if ((unsigned int)ret == 0x80410B07u) {
            snprintf(msg, sizeof(msg),
                     "adhocctlInit: 0x%08X (already initialized)",
                     (unsigned int)ret);
        } else if ((unsigned int)ret == 0x80410B13u) {
            snprintf(msg, sizeof(msg),
                     "adhocctlInit: 0x%08X (stack too small)",
                     (unsigned int)ret);
        } else {
            snprintf(msg, sizeof(msg),
                     "adhocctlInit: 0x%08X",
                     (unsigned int)ret);
        }

        stop_adhoc();
        show_message(ui_text("Erro", "Error"),
                     ui_text("Falha no controle Ad Hoc", "Ad Hoc control failure"),
                     msg,
                     ui_text("Verifique WLAN e reinicie o ADShare.",
                             "Check WLAN and restart ADShare."), C_ERROR);
        return 0;
    }
    g_adhocctl_initialized = 1;

    collect_device_info();

    ret = sceNetAdhocctlConnect(ADHOC_GROUP);
    if (ret < 0) {
        char msg[96];
        snprintf(msg, sizeof(msg), "adhocctlConnect: 0x%08X", (unsigned int)ret);
        stop_adhoc();
        show_message(ui_text("Erro", "Error"), ui_text("Nao foi possivel entrar no grupo", "Could not join group"), msg, "", C_ERROR);
        return 0;
    }

    if (!wait_adhoc_connected(12000)) {
        stop_adhoc();
        show_message(ui_text("Erro", "Error"),
                     ui_text("Timeout no Ad Hoc", "Ad Hoc timeout"),
                     ui_text("Os PSPs devem usar o mesmo canal.",
                             "Both PSPs must use the same channel."),
                     ui_text("Use SELECT para escolher Automatico/1/6/11.",
                             "Use SELECT to choose Auto/1/6/11."), C_ERROR);
        return 0;
    }

    g_adhoc_connected = 1;

    memset(&params, 0, sizeof(params));
    if (sceNetAdhocctlGetParameter(&params) >= 0) {
        g_connected_channel = params.channel;
        safe_copy(g_connected_group, params.name, sizeof(g_connected_group));
        if (params.nickname[0]) {
            safe_copy(g_local_nickname, params.nickname, sizeof(g_local_nickname));
            safe_copy(g_device.nickname, params.nickname, sizeof(g_device.nickname));
        }
    }

    if (sceWlanGetEtherAddr(g_local_mac) < 0) {
        stop_adhoc();
        show_message(ui_text("Erro", "Error"),
                     ui_text("Nao foi possivel obter o MAC WLAN",
                             "Could not read WLAN MAC"),
                     ui_text("Verifique o hardware de rede.",
                             "Check the network hardware."), "", C_ERROR);
        return 0;
    }

    /* Atualiza o MAC exibido depois que a WLAN estiver efetivamente ativa. */
    {
        char mac_text[32];
        mac_to_string(g_local_mac, mac_text, sizeof(mac_text));
        safe_copy(g_device.mac, mac_text, sizeof(g_device.mac));
    }

    g_pdp_id = sceNetAdhocPdpCreate(g_local_mac, CTRL_PORT, PDP_BUFFER_SIZE, 0);
    if (g_pdp_id < 0) {
        char msg[96];
        int pdp_error = g_pdp_id;
        g_pdp_id = -1;
        stop_adhoc();
        snprintf(msg, sizeof(msg), "PDP: 0x%08X", (unsigned int)pdp_error);
        show_message(ui_text("Erro", "Error"), ui_text("Falha no canal de descoberta", "Discovery channel failure"), msg, "", C_ERROR);
        return 0;
    }

    g_last_hello = 0;
    g_outgoing_waiting = 0;
    g_transfer_busy = 0;
    g_has_pending_offer = 0;
    memset(g_peers, 0, sizeof(g_peers));
    g_peer_count = 0;
    g_selected_peer = 0;
    set_status("Ad Hoc ativo - procurando consoles...", "Ad Hoc active - searching for consoles...");
    return 1;
}

static void stop_adhoc(void)
{
    if (g_pdp_id >= 0) {
        sceNetAdhocPdpDelete(g_pdp_id, 0);
        g_pdp_id = -1;
    }

    if (g_adhocctl_initialized) {
        if (g_adhoc_connected)
            sceNetAdhocctlDisconnect();

        sceNetAdhocctlTerm();
        g_adhocctl_initialized = 0;
    }

    if (g_adhoc_initialized) {
        sceNetAdhocTerm();
        g_adhoc_initialized = 0;
    }

    if (g_net_initialized) {
        sceNetTerm();
        g_net_initialized = 0;
    }

    g_adhoc_connected = 0;
    g_connected_channel = 0;
    g_outgoing_waiting = 0;
    g_transfer_busy = 0;
    g_has_pending_offer = 0;
}

/* =========================================================
   PEERS / CONTROLE PDP
   ========================================================= */

static int find_peer(const unsigned char* mac)
{
    int i;
    for (i = 0; i < MAX_PEERS; ++i)
        if (g_peers[i].used && mac_equal(g_peers[i].mac, mac))
            return i;
    return -1;
}

static int alloc_peer(void)
{
    int i;
    for (i = 0; i < MAX_PEERS; ++i)
        if (!g_peers[i].used)
            return i;
    return -1;
}

static void recount_peers(void)
{
    int i;
    g_peer_count = 0;
    for (i = 0; i < MAX_PEERS; ++i)
        if (g_peers[i].used)
            g_peer_count++;
}

static void touch_peer(const unsigned char* mac, const AdPacket* p)
{
    int i = find_peer(mac);
    if (i < 0)
        i = alloc_peer();
    if (i < 0)
        return;

    g_peers[i].used = 1;
    memcpy(g_peers[i].mac, mac, 6);
    g_peers[i].last_seen = now_us();

    if (p) {
        safe_copy(g_peers[i].nickname, p->nickname, sizeof(g_peers[i].nickname));
        safe_copy(g_peers[i].device, p->device, sizeof(g_peers[i].device));
        safe_copy(g_peers[i].firmware, p->firmware, sizeof(g_peers[i].firmware));
    }

    if (!g_peers[i].nickname[0]) {
        char full_nickname[128];
        memset(full_nickname, 0, sizeof(full_nickname));
        if (sceNetAdhocctlGetNameByAddr(g_peers[i].mac, full_nickname) >= 0)
            safe_copy(g_peers[i].nickname, full_nickname, sizeof(g_peers[i].nickname));
    }

    if (!g_peers[i].nickname[0])
        safe_copy(g_peers[i].nickname, "PSP", sizeof(g_peers[i].nickname));

    recount_peers();
}

static void prune_peers(void)
{
    int i;
    uint32_t now = now_us();

    for (i = 0; i < MAX_PEERS; ++i) {
        if (g_peers[i].used && (uint32_t)(now - g_peers[i].last_seen) > PEER_TIMEOUT_US)
            memset(&g_peers[i], 0, sizeof(g_peers[i]));
    }

    recount_peers();
}

static void fill_common_packet(AdPacket* p, int type)
{
    memset(p, 0, sizeof(*p));
    memcpy(p->magic, PROTOCOL_MAGIC, 4);
    p->version = PROTOCOL_VERSION;
    p->type = type;
    memcpy(p->sender_mac, g_local_mac, 6);
    safe_copy(p->nickname, g_local_nickname, sizeof(p->nickname));
    safe_copy(p->device, g_device.model, sizeof(p->device));
    safe_copy(p->firmware, g_device.firmware, sizeof(p->firmware));
}

static int send_packet_to(const unsigned char* mac, AdPacket* p)
{
    if (g_pdp_id < 0)
        return -1;

    return sceNetAdhocPdpSend(
        g_pdp_id,
        (unsigned char*)mac,
        CTRL_PORT,
        p,
        sizeof(*p),
        500000,
        0
    );
}

static void send_hello(void)
{
    static unsigned char broadcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    AdPacket p;
    fill_common_packet(&p, PKT_HELLO);
    send_packet_to(broadcast, &p);
    g_last_hello = now_us();
}

static void send_simple_response(const unsigned char* mac, int type, uint32_t token)
{
    AdPacket p;
    fill_common_packet(&p, type);
    p.token = token;
    send_packet_to(mac, &p);
}

static void poll_control_messages(void)
{
    while (g_pdp_id >= 0) {
        AdPacket p;
        unsigned char srcmac[6];
        unsigned short srcport = 0;
        int len = sizeof(p);
        int ret;

        memset(&p, 0, sizeof(p));
        ret = sceNetAdhocPdpRecv(
            g_pdp_id,
            srcmac,
            &srcport,
            &p,
            &len,
            0,
            1
        );

        if (ret < 0)
            break;

        if (len < 12 || memcmp(p.magic, PROTOCOL_MAGIC, 4) != 0 ||
            p.version != PROTOCOL_VERSION)
            continue;

        if (mac_equal(srcmac, g_local_mac))
            continue;

        touch_peer(srcmac, &p);

        switch (p.type) {
            case PKT_HELLO:
                break;

            case PKT_OFFER:
                if (g_has_pending_offer) {
                    /*
                     * O remetente repete a oferta ate receber resposta.
                     * Se for a mesma oferta ja exibida, apenas ignore o retry.
                     */
                    if (p.token != g_pending_offer.token ||
                        !mac_equal(srcmac, g_pending_offer_mac))
                        send_simple_response(srcmac, PKT_REJECT, p.token);
                } else if (!g_outgoing_waiting && !g_transfer_busy) {
                    g_pending_offer = p;
                    memcpy(g_pending_offer_mac, srcmac, 6);
                    g_has_pending_offer = 1;
                    set_status("Solicitacao de arquivo recebida", "File request received");
                } else {
                    /* Evita duas transferencias simultaneas no mesmo PSP. */
                    send_simple_response(srcmac, PKT_REJECT, p.token);
                }
                break;

            case PKT_ACCEPT:
                if (p.token == g_outgoing_token &&
                    mac_equal(srcmac, g_outgoing_peer_mac))
                    g_outgoing_response = 1;
                break;

            case PKT_REJECT:
            case PKT_CANCEL:
                if (p.token == g_outgoing_token &&
                    mac_equal(srcmac, g_outgoing_peer_mac))
                    g_outgoing_response = -1;
                break;

            case PKT_DONE:
                set_status("Transferencia concluida pelo outro PSP", "Transfer completed by the other PSP");
                break;
        }
    }

    if (elapsed_us(g_last_hello, HELLO_INTERVAL_US))
        send_hello();

    prune_peers();
}


/* =========================================================
   SELETOR DE CANAL AD HOC
   ========================================================= */

static const int g_channel_values[] = {
    PSP_SYSTEMPARAM_ADHOC_CHANNEL_AUTOMATIC,
    PSP_SYSTEMPARAM_ADHOC_CHANNEL_1,
    PSP_SYSTEMPARAM_ADHOC_CHANNEL_6,
    PSP_SYSTEMPARAM_ADHOC_CHANNEL_11
};

static const char* channel_value_name(int value)
{
    switch (value) {
        case PSP_SYSTEMPARAM_ADHOC_CHANNEL_AUTOMATIC:
            return ui_text("Automatico", "Automatic");
        case PSP_SYSTEMPARAM_ADHOC_CHANNEL_1:
            return ui_text("Canal 1", "Channel 1");
        case PSP_SYSTEMPARAM_ADHOC_CHANNEL_6:
            return ui_text("Canal 6", "Channel 6");
        case PSP_SYSTEMPARAM_ADHOC_CHANNEL_11:
            return ui_text("Canal 11", "Channel 11");
        default:
            return ui_text("Desconhecido", "Unknown");
    }
}

static int channel_value_index(int value)
{
    int i;
    int count = (int)(sizeof(g_channel_values) / sizeof(g_channel_values[0]));

    for (i = 0; i < count; ++i)
        if (g_channel_values[i] == value)
            return i;

    return 0;
}

static int apply_adhoc_channel(int value)
{
    int ret;
    int was_active =
        g_net_initialized || g_adhoc_initialized ||
        g_adhocctl_initialized || g_adhoc_connected ||
        g_pdp_id >= 0;

    if (g_transfer_busy || g_outgoing_waiting || g_has_pending_offer) {
        show_message(ui_text("Canal", "Channel"),
                     ui_text("Nao e possivel mudar agora", "Cannot change it now"),
                     ui_text("Finalize ou recuse a transferencia atual.",
                             "Finish or reject the current transfer."),
                     "", C_WARNING);
        return 0;
    }

    if (value != PSP_SYSTEMPARAM_ADHOC_CHANNEL_AUTOMATIC &&
        value != PSP_SYSTEMPARAM_ADHOC_CHANNEL_1 &&
        value != PSP_SYSTEMPARAM_ADHOC_CHANNEL_6 &&
        value != PSP_SYSTEMPARAM_ADHOC_CHANNEL_11) {
        show_message(ui_text("Canal", "Channel"),
                     ui_text("Canal invalido", "Invalid channel"),
                     ui_text("Use Automatico, 1, 6 ou 11.",
                             "Use Automatic, 1, 6 or 11."),
                     "", C_ERROR);
        return 0;
    }

    if (was_active) {
        set_status("Reiniciando Ad Hoc para trocar canal...",
                   "Restarting Ad Hoc to change channel...");
        stop_adhoc();
        sceKernelDelayThread(150000);
    }

    ret = sceUtilitySetSystemParamInt(
        PSP_SYSTEMPARAM_ID_INT_ADHOC_CHANNEL,
        value
    );

    if (ret < 0) {
        char msg[96];
        snprintf(msg, sizeof(msg), "sceUtilitySetSystemParamInt: 0x%08X",
                 (unsigned int)ret);
        collect_device_info();
        show_message(ui_text("Canal", "Channel"),
                     ui_text("Falha ao salvar canal", "Failed to save channel"),
                     msg, "", C_ERROR);

        if (was_active) {
            if (start_adhoc())
                send_hello();
        }
        return 0;
    }

    collect_device_info();

    if (was_active) {
        draw_loading("Ad Hoc", ui_text("Aplicando novo canal...", "Applying new channel..."));
        if (!start_adhoc()) {
            show_message(ui_text("Canal", "Channel"),
                         ui_text("Canal salvo, mas a rede falhou",
                                 "Channel saved, but network failed"),
                         ui_text("Pressione START/reabra o ADShare.",
                                 "Press START or reopen ADShare."),
                         ui_text("Verifique se a chave WLAN esta ligada.",
                                 "Make sure the WLAN switch is on."), C_WARNING);
            return 0;
        }
        send_hello();
    }

    snprintf(g_status_line, sizeof(g_status_line),
             "%s: %s",
             ui_text("Canal Ad Hoc", "Ad Hoc channel"),
             channel_value_name(value));
    return 1;
}

static int channel_selector_screen(void)
{
    int current = PSP_SYSTEMPARAM_ADHOC_CHANNEL_AUTOMATIC;
    int selected;
    int count =
        (int)(sizeof(g_channel_values) / sizeof(g_channel_values[0]));

    if (sceUtilityGetSystemParamInt(
            PSP_SYSTEMPARAM_ID_INT_ADHOC_CHANNEL,
            &current) < 0) {
        current = PSP_SYSTEMPARAM_ADHOC_CHANNEL_AUTOMATIC;
    }

    selected = channel_value_index(current);

    while (!osl_quit) {
        int i;

        oslStartDrawing();
        draw_background();

        draw_header(
            ui_text("Canal Ad Hoc", "Ad Hoc Channel"),
            "ADShare"
        );

        draw_panel(52, 48, 428, 218, C_PSN_BLUE);

        oslSetTextColor(C_TEXT);
        oslDrawString(
            center_x(
                ui_text(
                    "Selecione o canal dos dois PSPs",
                    "Select the channel for both PSPs"
                )
            ),
            64,
            ui_text(
                "Selecione o canal dos dois PSPs",
                "Select the channel for both PSPs"
            )
        );

        oslSetTextColor(C_TEXT_DIM);
        oslDrawString(
            center_x(
                ui_text(
                    "Ambos precisam usar o mesmo canal.",
                    "Both consoles must use the same channel."
                )
            ),
            84,
            ui_text(
                "Ambos precisam usar o mesmo canal.",
                "Both consoles must use the same channel."
            )
        );

        for (i = 0; i < count; ++i) {
            int y = 111 + i * 25;
            int selected_row = (i == selected);

            if (selected_row) {
                oslDrawFillRect(
                    75, y - 4, 405, y + 18,
                    C_HIGHLIGHT
                );
                oslDrawFillRect(
                    75, y - 4, 79, y + 18,
                    C_PSN_BLUE
                );
            }

            oslSetTextColor(
                selected_row ? C_TEXT : C_TEXT_DIM
            );

            oslDrawString(
                98,
                y,
                channel_value_name(g_channel_values[i])
            );

            if (g_channel_values[i] == current) {
                oslSetTextColor(C_SUCCESS);
                oslDrawString(
                    305,
                    y,
                    ui_text("Atual", "Current")
                );
            }
        }

        draw_footer(
            ui_text(
                "[X] Aplicar [QUADRADO] English [O] Cancelar",
                "[X] Apply [SQUARE] PT-BR [O] Cancel"
            )
        );

        oslEndDrawing();
        oslSyncFrame();
        oslReadKeys();

        if (osl_keys->pressed.down) {
            selected++;
            if (selected >= count)
                selected = 0;
        }

        if (osl_keys->pressed.up) {
            selected--;
            if (selected < 0)
                selected = count - 1;
        }

        if (osl_keys->pressed.square) {
            toggle_ui_language();
            collect_device_info();
        }

        if (osl_keys->pressed.circle)
            return 0;

        if (osl_keys->pressed.cross) {
            int value = g_channel_values[selected];

            if (value == current) {
                collect_device_info();
                return 1;
            }

            if (apply_adhoc_channel(value))
                return 1;

            if (sceUtilityGetSystemParamInt(
                    PSP_SYSTEMPARAM_ID_INT_ADHOC_CHANNEL,
                    &current) < 0) {
                current =
                    PSP_SYSTEMPARAM_ADHOC_CHANNEL_AUTOMATIC;
            }

            selected = channel_value_index(current);
        }
    }

    return 0;
}

static int peer_index_from_visible(int visible_index)
{
    int i, n = 0;
    for (i = 0; i < MAX_PEERS; ++i) {
        if (g_peers[i].used) {
            if (n == visible_index)
                return i;
            n++;
        }
    }
    return -1;
}

/* =========================================================
   TRANSFERENCIA DE DADOS - PDP CONFIAVEL
   ========================================================= */

/*
 * O PTP do PSP pode falhar em alguns firmwares/CFWs mesmo quando a
 * descoberta PDP funciona. A partir do ADShare 2.1, a transferencia usa
 * um segundo socket PDP e implementa confiabilidade no proprio protocolo:
 *
 *   HEADER -> HEADER_ACK
 *   CHUNK(seq, CRC32) -> ACK(seq)
 *   FIN -> FIN_ACK
 *
 * Cada pacote perdido e reenviado. ACK perdido tambem e recuperado, pois o
 * receptor reconhece sequencias duplicadas e envia o ACK novamente.
 *
 * O payload fica em 1024 bytes para permanecer pequeno e estavel no WLAN
 * Ad Hoc real do PSP.
 *
 * v2.1.1: no PSP real, retorno 0 de PdpSend/PdpRecv pode representar
 * sucesso; no receive o tamanho valido vem em *dataLength. Apenas valores
 * negativos sao erros de API.
 */

static uint32_t data_crc32(const unsigned char* data, int length)
{
    uint32_t crc = 0xFFFFFFFFu;
    int i;

    for (i = 0; i < length; ++i) {
        int bit;
        crc ^= data[i];

        for (bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }

    return ~crc;
}

static void data_packet_init(
    DataPacket* packet,
    int type,
    uint32_t token,
    uint32_t seq)
{
    memset(packet, 0, sizeof(*packet));
    memcpy(packet->magic, DATA_MAGIC, 4);
    packet->version = DATA_VERSION;
    packet->type = (uint8_t)type;
    packet->token = token;
    packet->seq = seq;
}

static int data_packet_valid(const DataPacket* packet, int wire_len)
{
    int expected;

    if (!packet)
        return 0;

    if (wire_len < DATA_PACKET_BASE_SIZE)
        return 0;

    if (memcmp(packet->magic, DATA_MAGIC, 4) != 0)
        return 0;

    if (packet->version != DATA_VERSION)
        return 0;

    if (packet->payload_len > DATA_CHUNK_SIZE)
        return 0;

    expected = DATA_PACKET_BASE_SIZE + packet->payload_len;
    if (wire_len < expected)
        return 0;

    return 1;
}

static int data_send_packet(
    int pdp,
    const unsigned char* dest_mac,
    unsigned short dest_port,
    const DataPacket* packet,
    int* error_out)
{
    int wire_len;
    int ret;

    if (!packet || !dest_mac)
        return 0;

    wire_len = DATA_PACKET_BASE_SIZE + packet->payload_len;

    /*
     * IMPORTANTE:
     * Em hardware PSP/implementacoes compativeis, retorno 0 pode significar
     * sucesso. Apenas valores NEGATIVOS sao tratados como erro.
     *
     * Isso tambem deixa o codigo compativel com implementacoes que retornam
     * a quantidade de bytes enviados.
     */
    ret = sceNetAdhocPdpSend(
        pdp,
        (unsigned char*)dest_mac,
        dest_port,
        (void*)packet,
        wire_len,
        1000000,
        0
    );

    if (ret < 0) {
        if (error_out)
            *error_out = ret;
        return 0;
    }

    if (error_out)
        *error_out = 0;

    return 1;
}

/*
 * Recebe um pacote do socket de dados e filtra pelo MAC/token.
 *
 * Retornos:
 *   1  pacote valido
 *   0  timeout/erro
 *  -1  pacote de outro peer/token (caller pode tentar novamente)
 */
static int data_recv_packet(
    int pdp,
    const unsigned char* expected_mac,
    uint32_t token,
    DataPacket* out,
    unsigned short* source_port,
    unsigned int timeout_us,
    int* error_out)
{
    unsigned char src_mac[6];
    unsigned short src_port = 0;
    int len = sizeof(*out);
    int ret;

    memset(out, 0, sizeof(*out));
    memset(src_mac, 0, sizeof(src_mac));

    /*
     * No PSP real, sceNetAdhocPdpRecv() usa o ponteiro "len" para informar
     * quantos bytes chegaram. Retorno 0 NAO deve ser interpretado como
     * timeout se len > 0.
     *
     * O proprio fluxo de controle do ADShare ja funcionava assim:
     *   ret < 0  -> erro/sem pacote
     *   ret >= 0 -> verificar len
     */
    ret = sceNetAdhocPdpRecv(
        pdp,
        src_mac,
        &src_port,
        out,
        &len,
        timeout_us,
        0
    );

    if (ret < 0) {
        if (error_out)
            *error_out = ret;
        return 0;
    }

    /*
     * Chamada sem erro mas sem payload. Nao e um codigo de erro 0x00000000.
     */
    if (len <= 0) {
        if (error_out)
            *error_out = 0;
        return 0;
    }

    if (len > (int)sizeof(*out)) {
        if (error_out)
            *error_out = 0;
        return -1;
    }

    if (!data_packet_valid(out, len)) {
        if (error_out)
            *error_out = 0;
        return -1;
    }

    if (expected_mac && !mac_equal(src_mac, expected_mac)) {
        if (error_out)
            *error_out = 0;
        return -1;
    }

    if (out->token != token) {
        if (error_out)
            *error_out = 0;
        return -1;
    }

    if (source_port)
        *source_port = src_port;

    if (error_out)
        *error_out = 0;

    return 1;
}

static int data_send_ack(
    int pdp,
    const unsigned char* dest_mac,
    unsigned short dest_port,
    int type,
    uint32_t token,
    uint32_t seq)
{
    DataPacket ack;
    int error = 0;

    data_packet_init(&ack, type, token, seq);
    return data_send_packet(pdp, dest_mac, dest_port, &ack, &error);
}

/*
 * Envia o mesmo pacote ate receber o ACK esperado.
 *
 * Retornos:
 *   1  confirmado
 *   0  falhou depois dos retries
 *  -1  peer cancelou
 */
static int data_send_with_ack(
    int pdp,
    const unsigned char* dest_mac,
    unsigned short dest_port,
    DataPacket* packet,
    int ack_type,
    int* last_error)
{
    int attempt;

    for (attempt = 0; attempt < DATA_RETRY_COUNT && !osl_quit; ++attempt) {
        DataPacket response;
        int err = 0;
        int recv_result;

        if (!data_send_packet(
                pdp, dest_mac, dest_port, packet, &err)) {
            if (last_error)
                *last_error = err;
            sceKernelDelayThread(50000);
            continue;
        }

        for (;;) {
            recv_result = data_recv_packet(
                pdp,
                dest_mac,
                packet->token,
                &response,
                NULL,
                DATA_ACK_TIMEOUT_US,
                &err
            );

            if (recv_result == 0) {
                if (last_error)
                    *last_error = err;
                break; /* timeout -> reenvia */
            }

            if (recv_result < 0)
                continue; /* pacote alheio/invalido */

            if (response.type == DATA_PKT_CANCEL)
                return -1;

            if (response.type == ack_type &&
                response.seq == packet->seq) {
                return 1;
            }

            /*
             * ACK antigo pode chegar atrasado. Ignora e continua aguardando
             * ate o timeout desta tentativa.
             */
        }
    }

    return 0;
}

/* =========================================================
   TELA DE TRANSFERENCIA
   ========================================================= */

static void draw_transfer_screen(
    const char* mode,
    const char* peer_name,
    const char* filename,
    uint64_t done,
    uint64_t total,
    uint32_t start_time)
{
    char size_text[96];
    char pct_text[32];
    char speed_text[64];
    char short_file[160];
    int pct = total ? (int)((done * 100ULL) / total) : 0;
    int bar = (pct * 360) / 100;
    uint32_t elapsed = now_us() - start_time;
    double seconds = elapsed / 1000000.0;
    double speed = seconds > 0.05 ? (done / 1048576.0) / seconds : 0.0;

    if (pct > 100)
        pct = 100;

    fit_text(filename, short_file, sizeof(short_file), 340);

    snprintf(
        size_text,
        sizeof(size_text),
        "%.2f MB / %.2f MB",
        done / 1048576.0,
        total / 1048576.0
    );

    snprintf(pct_text, sizeof(pct_text), "%d%%", pct);

    snprintf(
        speed_text,
        sizeof(speed_text),
        "%s %.2f MB/s",
        ui_text("Velocidade:", "Speed:"),
        speed
    );

    oslStartDrawing();
    draw_background();
    draw_header(APP_NAME, mode);

    draw_panel(24, 42, 456, 216, C_PSN_BLUE);
    draw_file_icon(45, 61, file_category(filename), 1);

    oslSetTextColor(C_TEXT);
    oslDrawString(88, 62, short_file);

    oslSetTextColor(C_TEXT_DIM);
    oslDrawString(88, 82, peer_name);

    oslDrawFillRect(58, 128, 418, 139, C_SCROLL_BG);
    oslDrawRect(58, 128, 418, 139, RGBA(80,80,90,255));

    if (bar > 0)
        oslDrawFillRect(58, 128, 58 + bar, 139, C_PSN_BLUE);

    oslSetTextColor(C_TEXT_DIM);
    oslDrawString(58, 103, size_text);
    oslDrawString(58, 154, speed_text);

    oslSetTextColor(C_TEXT);
    oslDrawString(390, 103, pct_text);

    oslSetTextColor(C_TEXT_DARK);
    oslDrawString(
        center_x(ui_text("[O] Cancelar transferencia",
                         "[O] Cancel transfer")),
        190,
        ui_text("[O] Cancelar transferencia",
                "[O] Cancel transfer")
    );

    oslEndDrawing();
    oslSyncFrame();
}

/* =========================================================
   TRANSFERENCIA - ENVIO PDP
   ========================================================= */

static int send_file_data(
    const unsigned char* dest_mac,
    const char* peer_name,
    const char* path,
    uint32_t token)
{
    SceIoStat st;
    SceUID fd = -1;
    int data_pdp = -1;
    int success = 0;
    int cancelled = 0;
    int last_error = 0;
    DataPacket packet;
    uint64_t total = 0;
    uint64_t sent = 0;
    uint32_t seq = 0;
    uint32_t started = 0;

    g_transfer_busy = 1;
    scePowerSetClockFrequency(333, 333, 166);

    memset(&st, 0, sizeof(st));

    if (sceIoGetstat(path, &st) < 0) {
        set_status("Nao foi possivel ler o arquivo",
                   "Could not read the file");
        goto cleanup;
    }

    total = (uint64_t)st.st_size;

    fd = sceIoOpen(path, PSP_O_RDONLY, 0);
    if (fd < 0) {
        set_status("Nao foi possivel abrir o arquivo",
                   "Could not open the file");
        goto cleanup;
    }

    draw_loading(
        ui_text("Envio", "Sending"),
        ui_text("Preparando canal de dados...", "Preparing data channel...")
    );

    data_pdp = sceNetAdhocPdpCreate(
        g_local_mac,
        DATA_CLIENT_PORT,
        DATA_PDP_BUFFER_SIZE,
        0
    );

    if (data_pdp < 0) {
        set_status_error(
            "Falha ao abrir canal de dados:",
            "Failed to open data channel:",
            data_pdp
        );
        goto cleanup;
    }

    /*
     * Pequena janela para o firmware registrar o novo PDP antes do primeiro
     * datagrama. O receptor ja abriu DATA_SERVER_PORT antes de enviar ACCEPT.
     */
    sceKernelDelayThread(120000);

    /*
     * HEADER confiavel.
     */
    data_packet_init(&packet, DATA_PKT_HEADER, token, 0);
    packet.file_size = total;
    sanitize_filename(
        base_name(path),
        packet.file_name,
        sizeof(packet.file_name)
    );

    {
        int result = data_send_with_ack(
            data_pdp,
            dest_mac,
            DATA_SERVER_PORT,
            &packet,
            DATA_PKT_HEADER_ACK,
            &last_error
        );

        if (result < 0) {
            set_status("O receptor cancelou a transferencia",
                       "Receiver cancelled the transfer");
            cancelled = 1;
            goto cleanup;
        }

        if (result == 0) {
            set_status_error(
                "Falha no handshake de dados:",
                "Data handshake failed:",
                last_error
            );
            goto cleanup;
        }
    }

    started = now_us();

    while (sent < total && !osl_quit) {
        int want;
        int read_bytes;
        int result;

        oslReadKeys();

        if (osl_keys->pressed.circle) {
            DataPacket cancel_packet;

            data_packet_init(
                &cancel_packet,
                DATA_PKT_CANCEL,
                token,
                seq
            );

            data_send_packet(
                data_pdp,
                dest_mac,
                DATA_SERVER_PORT,
                &cancel_packet,
                &last_error
            );

            cancelled = 1;
            set_status("Envio cancelado", "Send cancelled");
            break;
        }

        want = DATA_CHUNK_SIZE;

        if (total - sent < (uint64_t)want)
            want = (int)(total - sent);

        data_packet_init(
            &packet,
            DATA_PKT_CHUNK,
            token,
            seq
        );

        read_bytes = sceIoRead(fd, packet.payload, want);

        if (read_bytes <= 0) {
            set_status("Falha lendo o arquivo local",
                       "Failed to read local file");
            break;
        }

        packet.payload_len = (uint16_t)read_bytes;
        packet.crc32 = data_crc32(packet.payload, read_bytes);

        result = data_send_with_ack(
            data_pdp,
            dest_mac,
            DATA_SERVER_PORT,
            &packet,
            DATA_PKT_ACK,
            &last_error
        );

        if (result < 0) {
            cancelled = 1;
            set_status("O receptor cancelou a transferencia",
                       "Receiver cancelled the transfer");
            break;
        }

        if (result == 0) {
            set_status_error(
                "Conexao de dados interrompida:",
                "Data connection interrupted:",
                last_error
            );
            break;
        }

        sent += (uint64_t)read_bytes;
        seq++;

        draw_transfer_screen(
            ui_text("Enviando", "Sending"),
            peer_name,
            base_name(path),
            sent,
            total,
            started
        );
    }

    if (!cancelled && sent == total) {
        int result;

        data_packet_init(
            &packet,
            DATA_PKT_FIN,
            token,
            seq
        );

        result = data_send_with_ack(
            data_pdp,
            dest_mac,
            DATA_SERVER_PORT,
            &packet,
            DATA_PKT_FIN_ACK,
            &last_error
        );

        if (result == 1) {
            success = 1;
            set_status("Arquivo enviado com sucesso",
                       "File sent successfully");
        } else if (result < 0) {
            set_status("O receptor cancelou ao finalizar",
                       "Receiver cancelled while finishing");
        } else {
            set_status_error(
                "Arquivo enviado, mas sem confirmacao final:",
                "File sent, but final confirmation failed:",
                last_error
            );
        }
    }

cleanup:
    if (fd >= 0)
        sceIoClose(fd);

    if (data_pdp >= 0)
        sceNetAdhocPdpDelete(data_pdp, 0);

    if (success)
        send_simple_response(dest_mac, PKT_DONE, token);
    else
        send_simple_response(dest_mac, PKT_CANCEL, token);

    scePowerSetClockFrequency(222, 222, 111);
    g_transfer_busy = 0;
    return success;
}

/* =========================================================
   TRANSFERENCIA - RECEBIMENTO PDP
   ========================================================= */

static int receive_file_offer(
    const AdPacket* offer,
    const unsigned char* sender_mac)
{
    int data_pdp = -1;
    int last_error = 0;
    int timeout_count = 0;
    int accepted = 0;
    int success = 0;
    int cancelled = 0;
    uint32_t expected_seq = 0;
    uint64_t received = 0;
    uint32_t started = 0;
    unsigned short sender_data_port = DATA_CLIENT_PORT;
    DataPacket packet;
    char final_path[512] = {0};
    char part_path[544] = {0};
    SceUID fd = -1;

    if (!offer || !sender_mac)
        return 0;

    g_transfer_busy = 1;
    scePowerSetClockFrequency(333, 333, 166);

    draw_loading(
        ui_text("Receber", "Receive"),
        ui_text("Preparando canal de dados...", "Preparing data channel...")
    );

    data_pdp = sceNetAdhocPdpCreate(
        g_local_mac,
        DATA_SERVER_PORT,
        DATA_PDP_BUFFER_SIZE,
        0
    );

    if (data_pdp < 0) {
        send_simple_response(
            sender_mac,
            PKT_REJECT,
            offer->token
        );

        set_status_error(
            "Nao foi possivel abrir o receptor de dados:",
            "Could not open data receiver:",
            data_pdp
        );

        goto cleanup;
    }

    /*
     * Deixa o PDP de recepcao totalmente registrado antes de anunciar ACCEPT.
     */
    sceKernelDelayThread(120000);

    /*
     * O ACCEPT so e enviado depois que DATA_SERVER_PORT esta pronto.
     * Isso elimina a corrida que existia entre o aceite na UI e a criacao
     * do canal de transferencia.
     */
    send_simple_response(
        sender_mac,
        PKT_ACCEPT,
        offer->token
    );

    accepted = 1;

    draw_loading(
        ui_text("Receber", "Receive"),
        ui_text("Aguardando o remetente...", "Waiting for sender...")
    );

    /*
     * HEADER.
     */
    for (;;) {
        int rr = data_recv_packet(
            data_pdp,
            sender_mac,
            offer->token,
            &packet,
            &sender_data_port,
            12000000,
            &last_error
        );

        if (rr == 0) {
            set_status_error(
                "Timeout aguardando dados:",
                "Timed out waiting for data:",
                last_error
            );
            goto cleanup;
        }

        if (rr < 0)
            continue;

        if (packet.type == DATA_PKT_CANCEL) {
            cancelled = 1;
            set_status("O remetente cancelou a transferencia",
                       "Sender cancelled the transfer");
            goto cleanup;
        }

        if (packet.type != DATA_PKT_HEADER)
            continue;

        if (packet.file_size != offer->file_size ||
            strcmp(packet.file_name, offer->file_name) != 0) {
            set_status("Cabecalho de transferencia invalido",
                       "Invalid transfer header");
            goto cleanup;
        }

        data_send_ack(
            data_pdp,
            sender_mac,
            sender_data_port,
            DATA_PKT_HEADER_ACK,
            offer->token,
            packet.seq
        );

        break;
    }

    choose_receive_path(
        packet.file_name,
        final_path,
        sizeof(final_path)
    );

    if (!final_path[0]) {
        set_status("Nao foi possivel escolher destino",
                   "Could not choose destination");
        goto cleanup;
    }

    safe_copy(
        part_path,
        final_path,
        sizeof(part_path)
    );

    if (!safe_append(
            part_path,
            ".part",
            sizeof(part_path))) {
        set_status("Caminho de destino muito longo",
                   "Destination path is too long");
        goto cleanup;
    }

    fd = sceIoOpen(
        part_path,
        PSP_O_WRONLY | PSP_O_CREAT | PSP_O_TRUNC,
        0777
    );

    if (fd < 0) {
        set_status("Nao foi possivel criar o arquivo",
                   "Could not create the file");
        goto cleanup;
    }

    started = now_us();

    while (!osl_quit) {
        int rr;

        oslReadKeys();

        if (osl_keys->pressed.circle) {
            DataPacket cancel_packet;

            data_packet_init(
                &cancel_packet,
                DATA_PKT_CANCEL,
                offer->token,
                expected_seq
            );

            data_send_packet(
                data_pdp,
                sender_mac,
                sender_data_port,
                &cancel_packet,
                &last_error
            );

            cancelled = 1;
            set_status("Recebimento cancelado",
                       "Receive cancelled");
            break;
        }

        rr = data_recv_packet(
            data_pdp,
            sender_mac,
            offer->token,
            &packet,
            &sender_data_port,
            DATA_RECV_TIMEOUT_US,
            &last_error
        );

        if (rr == 0) {
            timeout_count++;

            if (timeout_count >= 3) {
                set_status_error(
                    "Conexao de dados perdida:",
                    "Data connection lost:",
                    last_error
                );
                break;
            }

            continue;
        }

        if (rr < 0)
            continue;

        timeout_count = 0;

        if (packet.type == DATA_PKT_CANCEL) {
            cancelled = 1;
            set_status("O remetente cancelou a transferencia",
                       "Sender cancelled the transfer");
            break;
        }

        /*
         * Se o ACK do HEADER se perdeu, o remetente reenviara o HEADER.
         * Responde novamente sem reiniciar o arquivo.
         */
        if (packet.type == DATA_PKT_HEADER) {
            data_send_ack(
                data_pdp,
                sender_mac,
                sender_data_port,
                DATA_PKT_HEADER_ACK,
                offer->token,
                packet.seq
            );
            continue;
        }

        if (packet.type == DATA_PKT_CHUNK) {
            uint32_t crc;

            if (packet.seq < expected_seq) {
                /*
                 * Chunk duplicado: o ACK anterior provavelmente se perdeu.
                 */
                data_send_ack(
                    data_pdp,
                    sender_mac,
                    sender_data_port,
                    DATA_PKT_ACK,
                    offer->token,
                    packet.seq
                );
                continue;
            }

            if (packet.seq > expected_seq) {
                /*
                 * Stop-and-wait nao deveria gerar pacote futuro.
                 * Ignora para que o remetente reenvie a sequencia esperada.
                 */
                continue;
            }

            if (packet.payload_len == 0 ||
                packet.payload_len > DATA_CHUNK_SIZE) {
                continue;
            }

            crc = data_crc32(
                packet.payload,
                packet.payload_len
            );

            if (crc != packet.crc32) {
                /* Nao envia ACK; sender reenviara automaticamente. */
                continue;
            }

            if (received + packet.payload_len >
                offer->file_size) {
                set_status("Pacote excedeu o tamanho esperado",
                           "Packet exceeded expected file size");
                break;
            }

            if (sceIoWrite(
                    fd,
                    packet.payload,
                    packet.payload_len) != packet.payload_len) {
                set_status("Falha gravando no armazenamento",
                           "Failed writing to storage");
                break;
            }

            received += packet.payload_len;

            data_send_ack(
                data_pdp,
                sender_mac,
                sender_data_port,
                DATA_PKT_ACK,
                offer->token,
                packet.seq
            );

            expected_seq++;

            draw_transfer_screen(
                ui_text("Recebendo", "Receiving"),
                offer->nickname,
                offer->file_name,
                received,
                offer->file_size,
                started
            );

            continue;
        }

        if (packet.type == DATA_PKT_FIN) {
            if (received != offer->file_size) {
                set_status("Arquivo incompleto no FIN",
                           "File incomplete at FIN");
                break;
            }

            /*
             * Fecha e finaliza ANTES do FIN_ACK. Assim o sender so recebe
             * sucesso depois que o arquivo realmente existe no destino.
             */
            if (fd >= 0) {
                sceIoClose(fd);
                fd = -1;
            }

            sceIoRemove(final_path);

            if (sceIoRename(part_path, final_path) < 0) {
                set_status("Recebido, mas falhou ao finalizar o arquivo",
                           "Received, but failed to finalize the file");
                break;
            }

            /*
             * Repetimos o FIN_ACK algumas vezes. PDP e datagrama; caso um
             * ACK final se perca, o sender ainda recebe outro.
             */
            {
                int i;

                for (i = 0; i < 4; ++i) {
                    data_send_ack(
                        data_pdp,
                        sender_mac,
                        sender_data_port,
                        DATA_PKT_FIN_ACK,
                        offer->token,
                        packet.seq
                    );

                    sceKernelDelayThread(25000);
                }
            }

            success = 1;
            set_status("Arquivo recebido com sucesso",
                       "File received successfully");
            break;
        }
    }

cleanup:
    if (fd >= 0)
        sceIoClose(fd);

    if (data_pdp >= 0)
        sceNetAdhocPdpDelete(data_pdp, 0);

    if (!success && part_path[0])
        sceIoRemove(part_path);

    if (success) {
        char short_path[160];

        send_simple_response(
            sender_mac,
            PKT_DONE,
            offer->token
        );

        fit_text(
            final_path,
            short_path,
            sizeof(short_path),
            400
        );

        show_message(
            ui_text("Concluido", "Completed"),
            ui_text("Arquivo recebido", "File received"),
            short_path,
            ui_text("Salvo automaticamente por categoria.",
                    "Saved automatically by category."),
            C_SUCCESS
        );
    } else if (accepted) {
        send_simple_response(
            sender_mac,
            PKT_CANCEL,
            offer->token
        );
    }

    (void)cancelled;
    scePowerSetClockFrequency(222, 222, 111);
    g_transfer_busy = 0;
    return success;
}

/* =========================================================
   OFERTA DE ARQUIVO
   ========================================================= */

static int send_offer_and_wait(
    const PeerInfo* peer,
    const char* path)
{
    SceIoStat st;
    AdPacket offer;
    uint32_t started;
    uint32_t last_send = 0;
    char file_size_text[64];
    char short_name[160];
    int result = 0;

    memset(&st, 0, sizeof(st));

    if (!peer ||
        !path ||
        sceIoGetstat(path, &st) < 0) {
        return 0;
    }

    fill_common_packet(&offer, PKT_OFFER);

    g_outgoing_token =
        now_us() ^
        ((uint32_t)g_local_mac[4] << 8) ^
        g_local_mac[5];

    offer.token = g_outgoing_token;
    offer.file_size = (uint64_t)st.st_size;

    sanitize_filename(
        base_name(path),
        offer.file_name,
        sizeof(offer.file_name)
    );

    safe_copy(
        offer.file_type,
        file_category(path),
        sizeof(offer.file_type)
    );

    memcpy(
        g_outgoing_peer_mac,
        peer->mac,
        6
    );

    g_outgoing_response = 0;
    g_outgoing_waiting = 1;
    started = now_us();

    format_size(
        offer.file_size,
        file_size_text,
        sizeof(file_size_text)
    );

    fit_text(
        offer.file_name,
        short_name,
        sizeof(short_name),
        390
    );

    while (!osl_quit &&
           (uint32_t)(now_us() - started) <
               OFFER_TIMEOUT_US) {

        if (last_send == 0 ||
            elapsed_us(last_send, 1200000u)) {
            send_packet_to(peer->mac, &offer);
            last_send = now_us();
        }

        poll_control_messages();

        if (g_outgoing_response == 1) {
            g_outgoing_waiting = 0;

            result = send_file_data(
                peer->mac,
                peer->nickname,
                path,
                g_outgoing_token
            );

            goto done;
        }

        if (g_outgoing_response < 0) {
            set_status(
                "O outro PSP recusou o arquivo",
                "The other PSP rejected the file"
            );
            goto done;
        }

        oslStartDrawing();
        draw_background();

        draw_header(
            APP_NAME,
            ui_text("Solicitacao", "Request")
        );

        draw_panel(
            28,
            59,
            452,
            205,
            C_PSN_BLUE
        );

        oslSetTextColor(C_TEXT);
        oslDrawString(
            center_x(
                ui_text(
                    "Aguardando confirmacao do outro PSP",
                    "Waiting for confirmation from the other PSP"
                )
            ),
            78,
            ui_text(
                "Aguardando confirmacao do outro PSP",
                "Waiting for confirmation from the other PSP"
            )
        );

        oslSetTextColor(C_TEXT_DIM);
        oslDrawString(
            50,
            111,
            ui_text("Destino:", "To:")
        );

        oslSetTextColor(C_TEXT);
        oslDrawString(
            125,
            111,
            peer->nickname
        );

        oslSetTextColor(C_TEXT_DIM);
        oslDrawString(
            50,
            136,
            ui_text("Arquivo:", "File:")
        );

        oslSetTextColor(C_TEXT);
        oslDrawString(
            125,
            136,
            short_name
        );

        oslSetTextColor(C_TEXT_DIM);
        oslDrawString(
            50,
            161,
            ui_text("Tamanho:", "Size:")
        );

        oslSetTextColor(C_TEXT);
        oslDrawString(
            125,
            161,
            file_size_text
        );

        draw_footer(
            ui_text(
                "[O] Cancelar solicitacao",
                "[O] Cancel request"
            )
        );

        oslEndDrawing();
        oslSyncFrame();
        oslReadKeys();

        if (osl_keys->pressed.circle) {
            send_simple_response(
                peer->mac,
                PKT_CANCEL,
                g_outgoing_token
            );

            set_status(
                "Solicitacao cancelada",
                "Request cancelled"
            );

            goto done;
        }

        sceKernelDelayThread(16000);
    }

    set_status(
        "Tempo esgotado aguardando resposta",
        "Timed out waiting for response"
    );

done:
    g_outgoing_waiting = 0;
    g_outgoing_response = 0;
    return result;
}


/* =========================================================
   FILE BROWSER
   ========================================================= */

static void path_parent(char* path)
{
    int len = strlen(path);
    char* slash;

    if (len <= 5)
        return;

    while (len > 5 && path[len - 1] == '/')
        path[--len] = '\0';

    slash = strrchr(path, '/');
    if (!slash)
        return;

    if (slash == path + 4)
        slash[1] = '\0';
    else
        *slash = '\0';
}

static int load_directory(const char* path, FileEntry* entries, int max_entries)
{
    SceUID d;
    SceIoDirent ent;
    int count = 0;

    d = sceIoDopen(path);
    if (d < 0)
        return 0;

    while (count < max_entries) {
        memset(&ent, 0, sizeof(ent));
        if (sceIoDread(d, &ent) <= 0)
            break;

        if (!strcmp(ent.d_name, ".") || !strcmp(ent.d_name, ".."))
            continue;

        safe_copy(entries[count].name, ent.d_name, sizeof(entries[count].name));
        entries[count].is_dir = FIO_S_ISDIR(ent.d_stat.st_mode) ? 1 : 0;
        entries[count].size = ent.d_stat.st_size;
        count++;
    }

    sceIoDclose(d);
    return count;
}

static int file_browser(char* selected_path, int selected_size)
{
    FileEntry entries[MAX_FILES];
    char current[512];
    int count;
    int sel = 0;
    int use_internal;

    if (directory_exists("ms0:/")) {
        safe_copy(current, "ms0:/", sizeof(current));
        use_internal = 0;
    } else {
        safe_copy(current, "ef0:/", sizeof(current));
        use_internal = 1;
    }

    while (!osl_quit) {
        int start;
        int i;
        int visible = 6;
        char path_display[160];

        poll_control_messages();

        if (g_has_pending_offer)
            return 0;

        count = load_directory(
            current,
            entries,
            MAX_FILES
        );

        if (sel >= count)
            sel = count > 0 ? count - 1 : 0;

        if (sel < 0)
            sel = 0;

        start = (sel / visible) * visible;

        oslStartDrawing();
        draw_background();

        draw_header(
            ui_text("Selecionar arquivo", "Select file"),
            "ADShare"
        );

        fit_text(
            current,
            path_display,
            sizeof(path_display),
            430
        );

        oslSetTextColor(C_TEXT_DIM);
        oslDrawString(15, 34, path_display);

        if (count == 0) {
            const char* empty =
                ui_text(
                    "Esta pasta esta vazia.",
                    "This folder is empty."
                );

            oslSetTextColor(C_TEXT_DIM);
            oslDrawString(
                center_x(empty),
                120,
                empty
            );
        }

        for (i = start;
             i < start + visible && i < count;
             ++i) {

            int row = i - start;
            int y = 58 + row * 30;
            char name_short[160];
            int selected = (i == sel);

            if (selected) {
                oslDrawFillRect(
                    10,
                    y - 3,
                    470,
                    y + 24,
                    C_HIGHLIGHT
                );

                oslDrawFillRect(
                    10,
                    y - 3,
                    13,
                    y + 24,
                    C_PSN_BLUE
                );
            }

            fit_text(
                entries[i].name,
                name_short,
                sizeof(name_short),
                320
            );

            if (entries[i].is_dir) {
                draw_folder_icon(
                    22,
                    y - 3,
                    selected
                );
            } else {
                draw_file_icon(
                    22,
                    y - 3,
                    file_category(entries[i].name),
                    selected
                );
            }

            oslSetTextColor(C_TEXT);
            oslDrawString(
                60,
                y + 3,
                name_short
            );

            if (!entries[i].is_dir) {
                char size_text[48];

                format_size(
                    (uint64_t)entries[i].size,
                    size_text,
                    sizeof(size_text)
                );

                oslSetTextColor(C_TEXT_DARK);
                oslDrawString(
                    390,
                    y + 3,
                    size_text
                );
            }
        }

        if (count > visible) {
            float h = 174.0f / count;
            float y = 58.0f + sel * h;

            oslDrawFillRect(
                474,
                58,
                477,
                232,
                C_SCROLL_BG
            );

            oslDrawFillRect(
                474,
                y,
                477,
                y + h * visible,
                C_SCROLL_BAR
            );
        }

        if (directory_exists("ef0:/")) {
            draw_footer(
                ui_text(
                    "[X] Abrir/Enviar  [O] Voltar  [L] ms0:/ef0:",
                    "[X] Open/Send     [O] Back    [L] ms0:/ef0:"
                )
            );
        } else {
            draw_footer(
                ui_text(
                    "[X] Abrir/Enviar              [O] Voltar",
                    "[X] Open/Send                 [O] Back"
                )
            );
        }

        oslEndDrawing();
        oslSyncFrame();
        oslReadKeys();

        if (osl_keys->pressed.square) {
            toggle_ui_language();
            collect_device_info();
        }

        if (osl_keys->pressed.down && count > 0) {
            sel++;
            if (sel >= count)
                sel = 0;
        }

        if (osl_keys->pressed.up && count > 0) {
            sel--;
            if (sel < 0)
                sel = count - 1;
        }

        if (osl_keys->pressed.L &&
            directory_exists("ef0:/")) {

            use_internal = !use_internal;

            safe_copy(
                current,
                use_internal ? "ef0:/" : "ms0:/",
                sizeof(current)
            );

            sel = 0;
        }

        if (osl_keys->pressed.circle) {
            if (strlen(current) > 5) {
                path_parent(current);
                sel = 0;
            } else {
                return 0;
            }
        }

        if (osl_keys->pressed.cross &&
            count > 0) {

            char next[512];

            join_path(
                current,
                entries[sel].name,
                next,
                sizeof(next)
            );

            if (entries[sel].is_dir) {
                safe_copy(
                    current,
                    next,
                    sizeof(current)
                );

                sel = 0;
            } else {
                safe_copy(
                    selected_path,
                    next,
                    selected_size
                );

                return 1;
            }
        }
    }

    return 0;
}


/* =========================================================
   DEVICE INFO SCREEN
   ========================================================= */

static void device_info_screen(void)
{
    int page = 0;

    collect_device_info();

    while (!osl_quit) {
        char free_mem[64];
        char header_right[96];
        char board_short[160];
        char model_short[96];
        char active_channel[48];
        int configured_channel =
            PSP_SYSTEMPARAM_ADHOC_CHANNEL_AUTOMATIC;

        poll_control_messages();

        if (g_has_pending_offer)
            return;

        snprintf(
            free_mem,
            sizeof(free_mem),
            "%.1f MB",
            sceKernelTotalFreeMemSize() / 1048576.0
        );

        snprintf(
            header_right,
            sizeof(header_right),
            "%s %s | %d/2",
            free_mem,
            ui_text("livres", "free"),
            page + 1
        );

        fit_text(
            g_device.board_family,
            board_short,
            sizeof(board_short),
            270
        );

        fit_text(
            g_device.model,
            model_short,
            sizeof(model_short),
            330
        );

        sceUtilityGetSystemParamInt(
            PSP_SYSTEMPARAM_ID_INT_ADHOC_CHANNEL,
            &configured_channel
        );

        if (g_connected_channel > 0 &&
            configured_channel ==
                PSP_SYSTEMPARAM_ADHOC_CHANNEL_AUTOMATIC) {

            snprintf(
                active_channel,
                sizeof(active_channel),
                "%s (%s %d)",
                ui_text("Automatico", "Automatic"),
                ui_text("ativo", "active"),
                g_connected_channel
            );

        } else if (g_connected_channel > 0) {
            snprintf(
                active_channel,
                sizeof(active_channel),
                "%s %d",
                ui_text("Canal", "Channel"),
                g_connected_channel
            );
        } else {
            safe_copy(
                active_channel,
                g_device.adhoc_channel,
                sizeof(active_channel)
            );
        }

        oslStartDrawing();
        draw_background();

        draw_header(
            ui_text(
                "Informacoes do dispositivo",
                "Device information"
            ),
            header_right
        );

        draw_panel(
            18,
            36,
            462,
            238,
            C_PSN_BLUE
        );

        draw_psp_icon(
            35,
            48,
            C_PSN_BLUE
        );

        oslSetTextColor(C_TEXT);
        oslDrawString(
            83,
            49,
            g_device.nickname
        );

        oslSetTextColor(C_TEXT_DIM);
        oslDrawString(
            83,
            67,
            model_short
        );

#define INFO_ROW(y, label, value) \
        do { \
            oslSetTextColor(C_TEXT_DIM); \
            oslDrawString(36, (y), (label)); \
            oslSetTextColor(C_TEXT); \
            oslDrawString(170, (y), (value)); \
        } while (0)

        if (page == 0) {
            INFO_ROW(
                94,
                ui_text("Modelo real:", "Real model:"),
                g_device.model
            );

            INFO_ROW(
                112,
                ui_text("Geracao:", "Generation:"),
                g_device.generation
            );

            INFO_ROW(
                130,
                "Firmware:",
                g_device.firmware
            );

            INFO_ROW(
                148,
                ui_text("Regiao/SKU:", "Region/SKU:"),
                g_device.region
            );

            INFO_ROW(
                166,
                ui_text("Idioma:", "System language:"),
                g_device.language
            );

            INFO_ROW(
                184,
                "MAC WLAN:",
                g_device.mac
            );

            INFO_ROW(
                202,
                ui_text("Canal Ad Hoc:", "Ad Hoc channel:"),
                active_channel
            );

            INFO_ROW(
                220,
                ui_text("Grupo:", "Group:"),
                g_connected_group
            );
        } else {
            char kernel_model[32];

            if (g_device.kernel_model_result >= 0) {
                snprintf(
                    kernel_model,
                    sizeof(kernel_model),
                    "%d (%s)",
                    g_device.kernel_model_result,
                    g_device.generation
                );
            } else {
                snprintf(
                    kernel_model,
                    sizeof(kernel_model),
                    "%s 0x%08X",
                    ui_text("Erro", "Error"),
                    (unsigned int)
                        g_device.kernel_model_result
                );
            }

            INFO_ROW(
                94,
                ui_text("Placa:", "Board:"),
                board_short
            );

            INFO_ROW(
                112,
                ui_text(
                    "Regiao IDStorage:",
                    "IDStorage region:"
                ),
                g_device.region_id_text
            );

            INFO_ROW(
                130,
                "Tachyon:",
                g_device.tachyon_text
            );

            INFO_ROW(
                148,
                "Baryon:",
                g_device.baryon_text
            );

            INFO_ROW(
                166,
                "Pommel:",
                g_device.pommel_text
            );

            INFO_ROW(
                184,
                "Kernel model:",
                kernel_model
            );

            INFO_ROW(
                202,
                "Probe:",
                g_device.probe_status_text
            );

            INFO_ROW(
                220,
                ui_text("Creditos:", "Credits:"),
                "welabsdev"
            );
        }

#undef INFO_ROW

        draw_footer(
            ui_text(
                "[L/R] Pagina [SELECT] Canal [QUADRADO] English [O] Voltar",
                "[L/R] Page [SELECT] Channel [SQUARE] PT-BR [O] Back"
            )
        );

        oslEndDrawing();
        oslSyncFrame();
        oslReadKeys();

        if (osl_keys->pressed.L ||
            osl_keys->pressed.R) {
            page = !page;
        }

        if (osl_keys->pressed.square) {
            toggle_ui_language();
            collect_device_info();
        }

        if (osl_keys->pressed.select) {
            channel_selector_screen();
            collect_device_info();
        }

        if (osl_keys->pressed.circle ||
            osl_keys->pressed.triangle) {
            return;
        }
    }
}


/* =========================================================
   INCOMING OFFER UI
   ========================================================= */

static void draw_incoming_offer(void)
{
    char size_text[64];
    char short_name[160];
    char sender[96];

    format_size(
        g_pending_offer.file_size,
        size_text,
        sizeof(size_text)
    );

    fit_text(
        g_pending_offer.file_name,
        short_name,
        sizeof(short_name),
        350
    );

    snprintf(
        sender,
        sizeof(sender),
        "%s %s",
        ui_text("De:", "From:"),
        g_pending_offer.nickname
    );

    draw_panel(
        30,
        58,
        450,
        207,
        C_WARNING
    );

    oslSetTextColor(C_WARNING);
    oslDrawString(
        center_x(
            ui_text(
                "Solicitacao de transferencia",
                "Transfer request"
            )
        ),
        74,
        ui_text(
            "Solicitacao de transferencia",
            "Transfer request"
        )
    );

    oslSetTextColor(C_TEXT);
    oslDrawString(
        52,
        105,
        sender
    );

    oslDrawString(
        52,
        130,
        short_name
    );

    oslSetTextColor(C_TEXT_DIM);
    oslDrawString(
        52,
        153,
        file_category_display(
            g_pending_offer.file_type
        )
    );

    oslDrawString(
        130,
        153,
        size_text
    );

    oslSetTextColor(C_TEXT);
    oslDrawString(
        center_x(
            ui_text(
                "[X] Aceitar                 [O] Recusar",
                "[X] Accept                 [O] Reject"
            )
        ),
        180,
        ui_text(
            "[X] Aceitar                 [O] Recusar",
            "[X] Accept                 [O] Reject"
        )
    );
}


/* =========================================================
   MAIN UI
   ========================================================= */

static void draw_connection_panel(int selected_peer_index)
{
    char local_mac[32];
    char channel_text[32];
    PeerInfo* peer = NULL;

    mac_to_string(
        g_local_mac,
        local_mac,
        sizeof(local_mac)
    );

    if (g_connected_channel > 0) {
        snprintf(
            channel_text,
            sizeof(channel_text),
            "%s %d",
            ui_text("Canal", "Channel"),
            g_connected_channel
        );
    } else {
        safe_copy(
            channel_text,
            ui_text(
                "Canal Automatico",
                "Automatic Channel"
            ),
            sizeof(channel_text)
        );
    }

    if (selected_peer_index >= 0 &&
        selected_peer_index < MAX_PEERS &&
        g_peers[selected_peer_index].used) {

        peer = &g_peers[selected_peer_index];
    }

    draw_panel(
        12,
        34,
        468,
        92,
        C_PSN_BLUE_SOFT
    );

    draw_psp_icon(
        24,
        49,
        C_PSN_BLUE
    );

    oslSetTextColor(C_TEXT);
    oslDrawString(
        65,
        46,
        g_local_nickname
    );

    oslSetTextColor(C_TEXT_DIM);
    oslDrawString(
        65,
        66,
        local_mac
    );

    oslSetTextColor(
        peer ? C_SUCCESS : C_TEXT_DARK
    );

    oslDrawString(
        223,
        53,
        peer ? "<====>" : "<  .  >"
    );

    if (peer) {
        char peer_mac[32];
        char name[72];

        mac_to_string(
            peer->mac,
            peer_mac,
            sizeof(peer_mac)
        );

        fit_text(
            peer->nickname,
            name,
            sizeof(name),
            130
        );

        draw_psp_icon(
            292,
            49,
            C_SUCCESS
        );

        oslSetTextColor(C_TEXT);
        oslDrawString(
            333,
            46,
            name
        );

        oslSetTextColor(C_TEXT_DIM);
        oslDrawString(
            333,
            66,
            peer_mac
        );
    } else {
        oslSetTextColor(C_TEXT_DIM);

        oslDrawString(
            293,
            51,
            ui_text(
                "Procurando PSPs...",
                "Searching for PSPs..."
            )
        );

        oslDrawString(
            293,
            70,
            channel_text
        );
    }
}


static void draw_main_screen(void)
{
    int i;
    int n = 0;
    int selected_real =
        peer_index_from_visible(g_selected_peer);
    int visible = 4;
    int start =
        (g_selected_peer / visible) * visible;

    oslStartDrawing();
    draw_background();

    draw_header(
        APP_NAME,
        "Ad Hoc  |  " ADHOC_GROUP
    );

    draw_connection_panel(selected_real);

    oslSetTextColor(C_TEXT_DIM);

    {
        char found[64];

        snprintf(
            found,
            sizeof(found),
            "%s %d",
            ui_text(
                "Consoles encontrados:",
                "Consoles found:"
            ),
            g_peer_count
        );

        oslDrawString(
            16,
            101,
            found
        );
    }

    if (g_peer_count == 0) {
        const char* line1 =
            ui_text(
                "Abra o ADShare em outro PSP.",
                "Open ADShare on another PSP."
            );

        const char* line2 =
            ui_text(
                "Os dois devem estar no mesmo canal Ad Hoc.",
                "Both must use the same Ad Hoc channel."
            );

        oslSetTextColor(C_TEXT_DIM);

        oslDrawString(
            center_x(line1),
            143,
            line1
        );

        oslDrawString(
            center_x(line2),
            163,
            line2
        );
    } else {
        for (i = 0; i < MAX_PEERS; ++i) {
            char name[96];
            char detail[160];
            int y;
            int selected;

            if (!g_peers[i].used)
                continue;

            if (n < start ||
                n >= start + visible) {
                n++;
                continue;
            }

            y = 120 + (n - start) * 29;
            selected = (n == g_selected_peer);

            if (selected) {
                oslDrawFillRect(
                    10,
                    y - 3,
                    470,
                    y + 23,
                    C_HIGHLIGHT
                );

                oslDrawFillRect(
                    10,
                    y - 3,
                    13,
                    y + 23,
                    C_PSN_BLUE
                );
            }

            fit_text(
                g_peers[i].nickname,
                name,
                sizeof(name),
                160
            );

            snprintf(
                detail,
                sizeof(detail),
                "%s | FW %s",
                g_peers[i].device[0]
                    ? g_peers[i].device
                    : "PSP",
                g_peers[i].firmware[0]
                    ? g_peers[i].firmware
                    : "?"
            );

            draw_psp_icon(
                25,
                y - 5,
                selected
                    ? C_PSN_BLUE
                    : RGBA(65,65,72,255)
            );

            oslSetTextColor(C_TEXT);
            oslDrawString(
                68,
                y,
                name
            );

            oslSetTextColor(C_TEXT_DIM);
            oslDrawString(
                222,
                y,
                detail
            );

            n++;
        }
    }

    oslSetTextColor(C_TEXT_DARK);

    {
        char status[160];

        fit_text(
            g_status_line,
            status,
            sizeof(status),
            440
        );

        oslDrawString(
            16,
            238,
            status
        );
    }

    draw_footer(
        ui_text(
            "[X] Enviar [SELECT] Canal [QUADRADO] English [TRIANGULO] Info [R] Buscar",
            "[X] Send [SELECT] Channel [SQUARE] PT-BR [TRIANGLE] Info [R] Search"
        )
    );

    if (g_has_pending_offer)
        draw_incoming_offer();

    oslEndDrawing();
    oslSyncFrame();
}


/* =========================================================
   START SCREEN
   ========================================================= */

static int start_screen(void)
{
    while (!osl_quit) {
        char version_text[48];
        char channel_line[96];
        const char* subtitle;
        const char* prompt;
        const char* offline;
        const char* credit;

        snprintf(
            version_text,
            sizeof(version_text),
            "%s %s",
            ui_text("Versao", "Version"),
            APP_VERSION
        );

        subtitle =
            ui_text(
                "Compartilhamento direto entre PSPs",
                "Direct sharing between PSPs"
            );

        prompt =
            ui_text(
                "Pressione [START] para ativar Ad Hoc",
                "Press [START] to enable Ad Hoc"
            );

        offline =
            ui_text(
                "Sem servidor, sem internet, PSP para PSP",
                "No server, no internet, PSP to PSP"
            );

        credit =
            ui_text(
                "Desenvolvido por welabsdev",
                "Developed by welabsdev"
            );

        snprintf(
            channel_line,
            sizeof(channel_line),
            "%s: %s",
            ui_text("Canal atual", "Current channel"),
            g_device.adhoc_channel
        );

        oslStartDrawing();
        draw_background();
        draw_header(
            APP_NAME,
            version_text
        );

        oslSetTextColor(C_TEXT);
        oslDrawString(
            center_x("A D S H A R E"),
            76,
            "A D S H A R E"
        );

        oslSetTextColor(C_PSN_BLUE);
        oslDrawString(
            center_x(subtitle),
            102,
            subtitle
        );

        draw_panel(
            70,
            132,
            410,
            174,
            C_PSN_BLUE_SOFT
        );

        oslSetTextColor(C_TEXT);
        oslDrawString(
            center_x(prompt),
            148,
            prompt
        );

        oslSetTextColor(C_TEXT_DIM);
        oslDrawString(
            center_x(offline),
            191,
            offline
        );

        oslDrawString(
            center_x(channel_line),
            210,
            channel_line
        );

        oslSetTextColor(C_TEXT_DARK);
        oslDrawString(
            center_x(credit),
            229,
            credit
        );

        draw_footer(
            ui_text(
                "[SELECT] Canal [QUADRADO] English [START] Iniciar",
                "[SELECT] Channel [SQUARE] PT-BR [START] Start"
            )
        );

        oslEndDrawing();
        oslSyncFrame();
        oslReadKeys();

        if (osl_keys->pressed.square) {
            toggle_ui_language();
            collect_device_info();
            set_status("Pronto", "Ready");
            continue;
        }

        if (osl_keys->pressed.select) {
            channel_selector_screen();
            collect_device_info();
            continue;
        }

        if (osl_keys->pressed.start)
            return 1;
    }

    return 0;
}


/* =========================================================
   MAIN
   ========================================================= */

int main(void)
{
    setup_callbacks();

    oslInit(0);
    oslInitGfx(OSL_PF_8888, 1);
    oslIntraFontInit(INTRAFONT_CACHE_ALL);

    g_font = oslLoadIntraFontFile("flash0:/font/ltn8.pgf", INTRAFONT_CACHE_ALL);
    if (g_font)
        oslSetFont(g_font);

    oslSetKeyAutorepeatInit(40);
    oslSetKeyAutorepeatInterval(5);

    init_ui_language();
    collect_device_info();
    set_status("Pronto", "Ready");

    if (!start_screen())
        goto exit_app;

    if (!start_adhoc())
        goto exit_app;

    send_hello();

    while (!osl_quit) {
        int selected_real;

        poll_control_messages();

        if (g_peer_count <= 0)
            g_selected_peer = 0;
        else {
            if (g_selected_peer >= g_peer_count)
                g_selected_peer = g_peer_count - 1;
            if (g_selected_peer < 0)
                g_selected_peer = 0;
        }

        draw_main_screen();
        oslReadKeys();

        /* Oferta recebida sempre tem prioridade. */
        if (g_has_pending_offer) {
            if (osl_keys->pressed.cross) {
                AdPacket offer = g_pending_offer;
                unsigned char sender[6];
                memcpy(sender, g_pending_offer_mac, 6);
                g_has_pending_offer = 0;
                receive_file_offer(&offer, sender);
                continue;
            }

            if (osl_keys->pressed.circle) {
                send_simple_response(g_pending_offer_mac, PKT_REJECT,
                                     g_pending_offer.token);
                g_has_pending_offer = 0;
                set_status("Arquivo recusado", "File rejected");
                continue;
            }

            continue;
        }

        if (osl_keys->pressed.down && g_peer_count > 0) {
            g_selected_peer++;
            if (g_selected_peer >= g_peer_count)
                g_selected_peer = 0;
        }

        if (osl_keys->pressed.up && g_peer_count > 0) {
            g_selected_peer--;
            if (g_selected_peer < 0)
                g_selected_peer = g_peer_count - 1;
        }

        if (osl_keys->pressed.R) {
            send_hello();
            set_status("Descoberta atualizada", "Discovery refreshed");
        }

        if (osl_keys->pressed.square) {
            toggle_ui_language();
            collect_device_info();
            set_status("Idioma alterado para Portugues (Brasil)",
                       "Language changed to English");
            continue;
        }

        if (osl_keys->pressed.select) {
            channel_selector_screen();
            collect_device_info();
            continue;
        }

        if (osl_keys->pressed.triangle) {
            device_info_screen();
            continue;
        }

        if (osl_keys->pressed.cross && g_peer_count > 0) {
            char selected_path[512];
            selected_real = peer_index_from_visible(g_selected_peer);

            if (selected_real >= 0 && g_peers[selected_real].used) {
                if (file_browser(selected_path, sizeof(selected_path))) {
                    /* Copia peer porque a lista pode ser atualizada durante espera. */
                    PeerInfo target = g_peers[selected_real];
                    send_offer_and_wait(&target, selected_path);
                }
            }
        }

        sceKernelDelayThread(16000);
    }

exit_app:
    stop_adhoc();

    if (g_font)
        oslDeleteFont(g_font);

    oslEndGfx();
    oslQuit();
    return 0;
}
