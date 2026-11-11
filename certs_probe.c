#include <ec.h>
#include <ec_plugins.h>
#include <ec_packet.h>
#include <ec_hook.h>

int plugin_load(void *);

static int certs_probe_init(void *);
static int certs_probe_fini(void *);
static int certs_probe_unload(void *);

static void certs_probe_handler(struct packet_object *po);
static void local_hexdump(unsigned char *data, size_t len);

struct plugin_ops certs_probe_ops = {
   .ettercap_version = EC_VERSION,
   .name             = "certs_probe",
   .info             = "HTTPS monitor with local dump",
   .version          = "1.0",
   .init             = certs_probe_init,
   .fini             = certs_probe_fini,
   .unload           = certs_probe_unload,
};

static void local_hexdump(unsigned char *data, size_t len) {
    size_t i;
    if (!data || len == 0) return;
    for (i = 0; i < len; i++) {
        USER_MSG("%02x ", data[i]);
        if ((i + 1) % 16 == 0) USER_MSG("\n");
    }
    USER_MSG("\n");
}

static char last_sni[256];
static char last_logged_ip[MAX_ASCII_ADDR_LEN];
static time_t last_time;
static const char* get_cipher_name(u_int8_t p1, u_int8_t p2) {
    u_int16_t cipher = (p1 << 8) | p2;
    if ((p1 == p2) && ((p1 & 0x0f) == 0x0a)) return "GREASE";
    switch (cipher) {
        case 0x1301: return "AES128-GCM";
        case 0x1302: return "AES256-GCM";
        case 0x1303: return "CHACHA20";
        case 0xc02b: return "ECDHE-ECDSA-AES128-GCM";
        case 0xc02f: return "ECDHE-RSA-AES128-GCM";
        case 0xc030: return "ECDHE-RSA-AES256-GCM";
        case 0xcca8: return "ECDHE-RSA-CHACHA20";
        default:     return "Unknown";
    }
}
static const char* get_tls_version_str(u_int8_t major, u_int8_t minor) {
    u_int16_t ver = (major << 8) | minor;
    switch (ver) {
        case 0x0304: return "1.3";
        case 0x0303: return "1.2";
        case 0x0302: return "1.1";
        case 0x0301: return "1.0";
        case 0x0300: return "SSL 3.0";
        default:     return "Unknown";
    }
}

static void scan_quic_sni(u_int8_t *p, size_t len, char *addr_str, char *dst_ip) {
    if (len < 40) return;
    if ((p[0] & 0x80) == 0) return;
    uint32_t v_num = (p[1] << 24) | (p[2] << 16) | (p[3] << 8) | p[4];
    for (size_t i = 0; i < len - 15; i++) {
        if (p[i] >= 'a' && p[i] <= 'z') {
            size_t j;
            int dots = 0;
            for (j = 0; j < 128 && (i + j) < len; j++) {
                u_int8_t c = p[i + j];
                if (c == '.') dots++;
                else if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) break;
            }
            if (dots >= 1 && j >= 5 && p[i + j - 1] != '.') {
                char version[16] = "Unknown";
                int is_known = 1;

                if (v_num == 0x00000001) snprintf(version, 16, "QUIC-1");
                else if (v_num == 0x6b3343cf) snprintf(version, 16, "QUIC-2");
                else if ((v_num & 0xff000000) == 0xff000000) snprintf(version, 16, "Draft-%d", p[4]);
                else if ((v_num & 0xffff0000) == 0x51300000 || (v_num & 0xffff0000) == 0x54300000) {
                    snprintf(version, 16, "GQUIC");
                } else {
                    is_known = 0;
                }

                USER_MSG("certs_probe: [%s] Domain:%.*s\n"
                         "certs_probe: [%s] Address: %s -> %s\n",
                         version, (int)j, &p[i], version, addr_str, dst_ip);

                if (!is_known) {
                    USER_MSG("DEBUG: Unknown QUIC Version Detected: 0x%08X\n", v_num);
                    char hex_dump[64] = {0};
                    for(int k = 0; k < 16 && k < len; k++) {
                        sprintf(hex_dump + (k * 3), "%02x ", p[k]);
                    }
                    USER_MSG("DEBUG: Packet Header Dump: %s\n", hex_dump);
                }
                return;
            }
        }
    }
}

static void certs_probe_handler(struct packet_object *po) {
    char addr_str[MAX_ASCII_ADDR_LEN];

    if (!po || !po->L4.header || po->DATA.len == 0 || !po->DATA.data)
        return;

    u_int16_t src_port = ntohs(po->L4.src);
    u_int16_t dst_port = ntohs(po->L4.dst);

    if (src_port != 443 && dst_port != 443) return;

    u_int8_t *p = po->DATA.data;
    size_t len = po->DATA.len;

    ip_addr_ntoa(&po->L3.src, addr_str);

    if (src_port == 443 || dst_port == 443) {
        int is_client_hello = 0;
        if (po->L4.proto == NL_TYPE_TCP && len > 5 && p[0] == 0x16 && p[5] == 0x01) {
            is_client_hello = 1;
        }
        else if (po->L4.proto == NL_TYPE_UDP && len > 0 && (p[0] & 0x80) && ((p[0] & 0x30) == 0x00)) {
            is_client_hello = 1;
        }
        if (is_client_hello && strcmp(last_logged_ip, addr_str) != 0) {
            USER_MSG("certs_probe: [Certificate Dispatched] Forward: %s\n", addr_str);
            strncpy(last_logged_ip, addr_str, MAX_ASCII_ADDR_LEN - 1);
        }
    }

    ip_addr_ntoa(&po->L3.src, addr_str);

    if (po->L4.proto == NL_TYPE_UDP) {
        char dst_ip[MAX_ASCII_ADDR_LEN];
        ip_addr_ntoa(&po->L3.dst, dst_ip);
        u_int8_t *p = po->DATA.data;

        if ((p[0] & 0x80) && ((p[0] & 0x30) == 0x00)) {
            scan_quic_sni(p, po->DATA.len, addr_str, dst_ip);
        }
        return;
    }

    if (len < 6 || p[0] != 0x16 || p[5] != 0x01) return;

    size_t pos = 5 + 38;

    if (pos + 1 > len) return;
    pos += 1 + p[pos];

    if (pos + 2 > len) return;
    u_int16_t cipher_len = (p[pos] << 8) | p[pos+1];
    
    size_t saved_cipher_pos = pos + 2;
    for (size_t i = 0; i < cipher_len; i += 2) {
        size_t current_pos = pos + 2 + i;
        if (current_pos + 1 >= len) break;
        u_int8_t p1 = p[current_pos];
        u_int8_t p2 = p[current_pos + 1];
        if (!((p1 == p2) && ((p1 & 0x0f) == 0x0a))) {
            saved_cipher_pos = current_pos;
            break;
        }
    }
    pos += 2 + cipher_len;

    if (pos + 1 > len) return;
    pos += 1 + p[pos];

    if (pos + 2 > len) return;
    u_int16_t ext_total_len = (p[pos] << 8) | p[pos+1];
    pos += 2;

    size_t ext_end = pos + ext_total_len;

    if (ext_end > len) ext_end = len;

    if (p[0] != 0x16) return;

    const char *ver_str = get_tls_version_str(p[9], p[10]); 

    u_int16_t name_len = 0;
    u_int8_t *name_ptr = NULL;

    while (pos + 4 <= ext_end) {
        u_int16_t ext_type = (p[pos] << 8) | p[pos+1];
        u_int16_t ext_len  = (p[pos+2] << 8) | p[pos+3];
        pos += 4;
        if (pos + ext_len > ext_end) break;

        if (ext_type == 0x002b && ext_len >= 3) {
            u_int8_t list_len = p[pos];
            for (u_int16_t i = 1; i + 1 <= ext_len && i <= list_len; i += 2) {
                if (p[pos+i] == 0x03 && p[pos+i+1] == 0x04) {
                    ver_str = "1.3";
                    break;
                }
                if (p[pos+i] == 0x03 && p[pos+i+1] == 0x03) {
                    ver_str = "1.2";
                }
            }
        }

        if (ext_type == 0x0000 && pos + 5 <= ext_end && p[pos+2] == 0x00) {
            name_len = (p[pos+3] << 8) | p[pos+4];
            if (pos + 5 + name_len <= ext_end) {
                name_ptr = &p[pos+5];
            }
        }
        pos += ext_len;
    }

    if (name_ptr) {
        if ( (strlen(last_sni) != name_len || strncmp(last_sni, (char *)name_ptr, name_len) != 0)
            || (time(NULL) - last_time > 60) ) {
                USER_MSG("certs_probe: [Handshake Detected] From: %s (TLSv%s)\n",
                    addr_str, ver_str);
                USER_MSG("certs_probe: [Client Hello] From: %s\n", addr_str);
                USER_MSG("certs_probe: [Target Domain] %.*s (Cipher %s)\n", 
                    name_len, name_ptr, get_cipher_name(p[saved_cipher_pos], p[saved_cipher_pos+1]));
            last_time = time(NULL);
            size_t copy_len = (name_len > 255) ? 255 : name_len;
            memcpy(last_sni, name_ptr, copy_len);
            last_sni[copy_len] = '\0';
        }
    }
}

int plugin_load(void *handle) {
    return plugin_register(handle, &certs_probe_ops);
}

static int certs_probe_init(void *data) {
    (void)data;
    USER_MSG("certs_probe: plugin running...\n");
    hook_add(HOOK_PACKET_TCP, certs_probe_handler);
    hook_add(HOOK_PACKET_UDP, certs_probe_handler);
    return PLUGIN_RUNNING;
}

static int certs_probe_fini(void *data) {
    (void)data;
    USER_MSG("certs_probe: plugin terminated...\n");
    hook_del(HOOK_PACKET_TCP, certs_probe_handler);
    hook_del(HOOK_PACKET_UDP, certs_probe_handler);
    return PLUGIN_FINISHED;
}

static int certs_probe_unload(void *handle) {
   (void)handle;
   USER_MSG("certs_probe: plugin dump clean-up\n");
   return PLUGIN_UNLOADED;
}
