#include "libibackup.h"
#include "endianness.h"

#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <plist/plist.h>
#include <libimobiledevice-glue/sha.h>
#include <libimobiledevice-glue/collection.h>
#include <openssl/evp.h>
#include <openssl/err.h>

enum {
	LIMD_DEBUG = 7
};

static void LIMD_log_message(int level, const char* domain, const char* msg, ...)
{
	va_list va;
	va_start(va, msg);
	printf("[%s] ", domain);
	vprintf(msg, va);
	va_end(va);
}

int64_t libibackup_manifest_query_count(sqlite3* database, const char* query, const char* parameter) {
    sqlite3_stmt *count_statement;

    assert(database);
    assert(query);

    LIMD_log_message(LIMD_DEBUG, "backup", "Preparing Count Statement\n");

    sqlite3_prepare_v3(database, query, strlen(query), SQLITE_PREPARE_NORMALIZE, &count_statement, NULL);

    if (parameter != NULL) {
        sqlite3_bind_text(count_statement, 1, parameter, strlen(parameter), NULL);
    }

    if (sqlite3_step(count_statement) != SQLITE_ROW) {
        return IBACKUP_E_DATA_ERROR;
    }

    uint64_t count = sqlite3_column_int64(count_statement, 0);

    LIMD_log_message(LIMD_DEBUG, "backup", "Read count %llu\n", count);

    sqlite3_finalize(count_statement);

    LIMD_log_message(LIMD_DEBUG, "backup", "Finalizing Domain Count Statement\n");

    return count;
}

char* libibackup_ensure_directory(const char* path) {
    assert(path);

    char* full_path;

    if (path[strlen(path) - 1] != PATH_SEPARATOR[0]) {
        full_path = malloc(strlen(path) + 2);
        strcpy(full_path, path);
        strcat(full_path, PATH_SEPARATOR);
    }
    else {
        full_path = malloc(strlen(path) + 1);
        strcpy(full_path, path);
    }

    return full_path;
}

EXPORT char* libibackup_combine_path(const char* directory, const char* file) {
    assert(directory);
    assert(file);

    char* full_path;
    char* file_path;

    full_path = libibackup_ensure_directory(directory);

    file_path = malloc(strlen(full_path) + strlen(file) + 1);
    strcpy(file_path, full_path);
    strcat(file_path, file);

    free(full_path);

    return file_path;
}

plist_t libibackup_load_plist(const char* directory, const char* file) {
    plist_t plist;
    char* data;
    struct stat path_stat;
    FILE* file_handle;

    char* file_path = libibackup_combine_path(directory, file);
    stat(file_path, &path_stat);

    data = malloc(path_stat.st_size);

    file_handle = fopen(file_path, "r");
    fread(data, 1, path_stat.st_size, file_handle);
    fclose(file_handle);

    plist_from_memory(data, path_stat.st_size, &plist, NULL);

    free(file_path);

    return plist;
}

bool libibackup_preflight_test_file(const char* directory, const char* file) {
    struct stat path_stat;
    char* file_path;

    file_path = libibackup_combine_path(directory, file);

    stat(file_path, &path_stat);
    free(file_path);

    return S_ISREG(path_stat.st_mode);
}

EXPORT bool libibackup_preflight_backup(const char* path) {
    struct stat path_stat;
    stat(path, &path_stat);

    if (!S_ISDIR(path_stat.st_mode)) {
        return false;
    }

    return libibackup_preflight_test_file(path, "Info.plist") &&
            libibackup_preflight_test_file(path, "Manifest.plist") &&
            libibackup_preflight_test_file(path, "Manifest.db");
}

EXPORT libibackup_error_t libibackup_get_file_by_id(libibackup_client_t client, const char* file_id, char** full_path)
{
    char* file_component = malloc(strlen(file_id) + 4);
    file_component[0] = file_id[0];
    file_component[1] = file_id[1];
    file_component[2] = PATH_SEPARATOR[0];
    strncpy(file_component + 3, file_id, strlen(file_id));

    char* path = libibackup_combine_path(client->path, file_component);
    *full_path = path;
    free(file_component);

    LIMD_log_message(LIMD_DEBUG, "backup", "Full File Path for %s is %s\n", file_id, path);

    return IBACKUP_E_SUCCESS;
}

EXPORT libibackup_error_t libibackup_remove_file_by_id(libibackup_client_t client, const char* file_id) {
    sqlite3_stmt *delete_file_statement;
    char* file_path;
    libibackup_get_file_by_id(client, file_id, &file_path);

    sqlite3_prepare_v3(client->manifest, delete_file_query, strlen(delete_file_query), SQLITE_PREPARE_NORMALIZE, &delete_file_statement, NULL);

    sqlite3_bind_text(delete_file_statement, 1, file_path, strlen(file_path), NULL);

    sqlite3_step(delete_file_statement);

    return IBACKUP_E_SUCCESS;
}

EXPORT char* libibackup_get_path_for_file_id(libibackup_client_t client, const char* file_id) {
    char* file_path = malloc(strlen(file_id) + 4);
    file_path[0] = file_id[0];
    file_path[1] = file_id[1];
    file_path[2] = PATH_SEPARATOR[0];
    strcpy(file_path + 3, file_id);

    return libibackup_combine_path(client->path, file_path);
}

EXPORT libibackup_error_t libibackup_add_file(libibackup_client_t client, const char* domain, const char* relative_path, const void* data, const size_t length) {
    assert(client);
    
    unsigned char file_hash[SHA1_DIGEST_LENGTH];
    sha1(data, length, file_hash);

    char* file_hash_str = (char*)malloc(SHA1_DIGEST_LENGTH*2 + 1);
    for (int i = 0; i < SHA1_DIGEST_LENGTH; i++) {
        snprintf(file_hash_str + i*2, 2, "%02x", file_hash[i]);
    }
    file_hash_str[SHA1_DIGEST_LENGTH*2] = '\0';

    char* full_data_path = libibackup_get_path_for_file_id(client, (const char*)file_hash_str);
    free(file_hash_str);

    FILE* output_data_file = fopen(full_data_path, "w");

    fwrite(data, length, 1, output_data_file);

    fclose(output_data_file);

    sqlite3_stmt *insert_file_statement;
    sqlite3_prepare_v3(client->manifest, create_new_file_query, strlen(create_new_file_query), SQLITE_PREPARE_NORMALIZE, &insert_file_statement, NULL);

    if (sqlite3_step(insert_file_statement) != SQLITE_DONE) {

    }

    return IBACKUP_E_SUCCESS;
}

EXPORT libibackup_error_t libibackup_get_raw_metadata_by_id(libibackup_client_t client, const char* file_id, plist_t* metadata) {
    sqlite3_stmt *query_metadata;

    LIMD_log_message(LIMD_DEBUG, "backup", "Query for Metadata for ID %s\n", file_id);

    sqlite3_prepare_v3(client->manifest, file_metadata_query, strlen(file_metadata_query), SQLITE_PREPARE_NORMALIZE, &query_metadata, NULL);

    sqlite3_bind_text(query_metadata, 1, file_id, strlen(file_id), NULL);

    if (sqlite3_step(query_metadata) == SQLITE_ROW) {
        LIMD_log_message(LIMD_DEBUG, "backup", "Metadata for file found\n");

        const void* metadata_blob = sqlite3_column_blob(query_metadata, 0);
        int metadata_size = sqlite3_column_bytes(query_metadata, 0);

        plist_from_memory(metadata_blob, metadata_size, metadata, NULL);
    }

    return IBACKUP_E_SUCCESS;
}

/*
int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
                      const unsigned char *salt, int saltlen, int iter,
                      const EVP_MD *digest,
                      int keylen, unsigned char *out);
*/

static void derive_key_from_password(libibackup_client_t client, const char* password, unsigned char key[32], int iOS_10_2_or_newer)
{
    int pass_len = strlen(password);
    unsigned char temp_key[32];
    if (iOS_10_2_or_newer) {
        int dpic = (int)plist_dict_get_uint(client->keybag_dict, "DPIC");
        uint64_t dpsl_len = 0;
        plist_t p_dpsl = plist_dict_get_item(client->keybag_dict, "DPSL");
        const unsigned char* dpsl = (const unsigned char*)plist_get_data_ptr(p_dpsl, &dpsl_len);
        PKCS5_PBKDF2_HMAC(password, pass_len, dpsl, (int)dpsl_len, dpic, EVP_sha256(), 32, temp_key);
        password = (const char*)&temp_key[0];
        pass_len = 32;
    }
    int iter = (int)plist_dict_get_uint(client->keybag_dict, "ITER");
    plist_t p_salt = plist_dict_get_item(client->keybag_dict, "SALT");
    uint64_t salt_len = 0;
    const unsigned char* salt = (const unsigned char*)plist_get_data_ptr(p_salt, &salt_len);
    //unsigned char key_out[32];
    PKCS5_PBKDF2_HMAC(password, pass_len, salt, (int)salt_len, iter, EVP_sha1(), 32, key);
    //client->decryption_key = plist_new_data((char*)key_out, 32);
    //plist_print(client->decryption_key);
}

#define DEVICE_VERSION(maj, min, patch) (((maj & 0xFF) << 16) | ((min & 0xFF) << 8) | (patch & 0xFF))

static uint32_t numeric_device_version(const char* product_version)
{
    int vers[3] = {0, 0, 0};
    if (product_version && sscanf(product_version, "%d.%d.%d", &vers[0], &vers[1], &vers[2]) >= 2) {
        return DEVICE_VERSION(vers[0], vers[1], vers[2]);
    }
    return 0;
}

static int load_keys(libibackup_client_t client)
{
    uint64_t keybag_size = 0;
    plist_t p_backup_keybag = plist_dict_get_item(client->manifest_info, "BackupKeyBag");
    const unsigned char* keybag = (unsigned char*)plist_get_data_ptr(p_backup_keybag, &keybag_size);
    if (!keybag) {
        return -1;
    }

    plist_t keybag_dict = plist_new_dict();
    plist_t class_keys = plist_new_dict();
    plist_t current_class_key = NULL;

    const unsigned char* p = keybag;

    while (p+4 < keybag + keybag_size) {
        if (p[4] != '\0') {
            printf("Failed to parse keybag!\n");
            break;
        }
        char* p_tag = (char*)p;
        uint32_t tag = be32toh(*(uint32_t*)p);
        p += 4;
        uint32_t len = be32toh(*(uint32_t*)p);
        p += 4;
        if (tag == 'VERS') {
            plist_dict_set_item(keybag_dict, "version", plist_new_uint(be32toh(*(uint32_t*)p)));
        }
        else if (tag == 'TYPE') {
            uint32_t type = be32toh(*(uint32_t*)p);
            plist_dict_set_item(keybag_dict, "type", plist_new_uint(type));
            if (type > 3) {
                printf("FAIL: keybag type > 3: %d\n", type);
            }
        }
        else if (tag == 'UUID' && plist_dict_get_item(keybag_dict, "UUID") == NULL) {
            plist_dict_set_item(keybag_dict, "UUID", plist_new_data((char*)p, len));
        }
        else if (tag == 'WRAP' && plist_dict_get_item(keybag_dict, "WRAP") == NULL) {
            plist_dict_set_item(keybag_dict, "WRAP", plist_new_uint(be32toh(*(uint32_t*)p)));
        }
        else if (tag == 'ITER' && plist_dict_get_item(keybag_dict, "ITER") == NULL) {
            plist_dict_set_item(keybag_dict, "ITER", plist_new_uint(be32toh(*(uint32_t*)p)));
        }
        else if (tag == 'DPWT' && plist_dict_get_item(keybag_dict, "DPWT") == NULL) {
            plist_dict_set_item(keybag_dict, "DPWT", plist_new_uint(be32toh(*(uint32_t*)p)));
        }
        else if (tag == 'DPIC' && plist_dict_get_item(keybag_dict, "DPIC") == NULL) {
            plist_dict_set_item(keybag_dict, "DPIC", plist_new_uint(be32toh(*(uint32_t*)p)));
        }
        else if (tag == 'UUID') {
            if (current_class_key) {
                uint32_t clas = (uint32_t)plist_dict_get_uint(current_class_key, "CLAS");
                char clas_str[8];
                snprintf(clas_str, 8, "%u", clas);
                plist_dict_set_item(class_keys, clas_str, current_class_key);
            }
            current_class_key = plist_new_dict();
            plist_dict_set_item(current_class_key, "UUID", plist_new_data((char*)p, len));
        }
        else if (current_class_key && (tag == 'CLAS' || tag == 'WRAP' || tag == 'KTYP')) {
            plist_dict_set_item(current_class_key, p_tag, plist_new_uint(be32toh(*(uint32_t*)p)));
        }
        else if (current_class_key && (tag == 'WPKY' || tag == 'PBKY')) {
            plist_dict_set_item(current_class_key, p_tag, plist_new_data((char*)p, len));
        }
        else {
            plist_dict_set_item(keybag_dict, p_tag, plist_new_data((char*)p, len));
        }
        p += len;
    }
    if (current_class_key) {
        uint32_t clas = (uint32_t)plist_dict_get_uint(current_class_key, "CLAS");
        char clas_str[8];
        snprintf(clas_str, 8, "%u", clas);
        plist_dict_set_item(class_keys, clas_str, current_class_key);
    }
    plist_dict_set_item(keybag_dict, "classkeys", class_keys);
    plist_print(keybag_dict);
    client->keybag_dict = keybag_dict;

    return 0;
}

static void hexdump(void* ptr, int len)
{
    for (int i = 0; i < len; i++) {
        printf("%02x ", ((unsigned char*)ptr)[i]);
    }
    printf("\n");
}

static void aes_unwrap(unsigned char* dec_key, unsigned char* wrapped_key, int wrapped_key_len, unsigned char* key_out, int* key_out_len)
{
    int i, j;
    int num_qwords = wrapped_key_len / 8;
    uint64_t* C = (uint64_t*)calloc(1, sizeof(uint64_t) * num_qwords);
    uint64_t* R = (uint64_t*)calloc(1, sizeof(uint64_t) * num_qwords);
    for (i = 0; i < num_qwords; i++) {
        C[i] = be64toh(*(uint64_t*)(&wrapped_key[i*8]));
        if (i > 0) {
            R[i] = C[i];
        }
    }
    uint64_t A = C[0];
    int n = num_qwords-1;
    unsigned char todec[16];
    unsigned char decod[32];

    for (j = 5; j >= 0; j--) {
        //printf("j = %d\n", j);
        for (i = n; i > 0; i--) {
            //printf("i = %d\n", i);

            *(uint64_t*)(&todec[0]) = htobe64(A ^ (n*j+i));
            *(uint64_t*)(&todec[8]) = htobe64(R[i]);

            //hexdump(todec, 16);

            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            EVP_CIPHER_CTX_set_padding(ctx, 0);
            EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, dec_key, NULL);
            int todec_len = 16;
            int decod_len = 16;
            EVP_DecryptUpdate(ctx, decod, &decod_len, todec, todec_len);
            EVP_DecryptFinal_ex(ctx, decod+decod_len, &decod_len);
            EVP_CIPHER_CTX_free(ctx);

            //hexdump(decod, 16);

            A = be64toh(*(uint64_t*)&decod[0]);
            R[i] = be64toh(*(uint64_t*)(&decod[8]));
        }
    }
    if (A != 0xa6a6a6a6a6a6a6a6) {
        printf("None\n");
    }
    for (i = 0; i < n; i++) {
        *(uint64_t*)(key_out+i*8) = htobe64(R[i+1]);
    }
    *key_out_len = n*8;
}

#define WRAP_PASSCODE 2

static int unlock_keys(libibackup_client_t client)
{
    if (!client->decryption_key) {
        return 0;
    }
    plist_dict_iter iter;
    plist_t classkeys = plist_dict_get_item(client->keybag_dict, "classkeys");
    plist_dict_new_iter(classkeys, &iter);
    if (iter) {
        plist_t node = NULL;
        char* key = NULL;
        do {
            plist_dict_next_item(classkeys, iter, &key, &node);
            if (node) {
                plist_t p_wpky = plist_dict_get_item(node, "WPKY");
                if (p_wpky && (plist_dict_get_uint(node, "WRAP") & WRAP_PASSCODE)) {
                    uint64_t keylen = 0;
                    unsigned char* dec_key = (unsigned char*)plist_get_data_ptr(client->decryption_key, &keylen);
                    uint64_t wpky_len = 0;
                    unsigned char* wpky = (unsigned char*)plist_get_data_ptr(p_wpky, &wpky_len);
                    unsigned char* key_out = (unsigned char*)malloc(wpky_len);
                    int key_out_len = 0;
                    aes_unwrap(dec_key, wpky, (int)wpky_len, key_out, &key_out_len);
                    hexdump(key_out, key_out_len);
                    plist_dict_set_item(node, "KEY", plist_new_data((char*)key_out, key_out_len));
                    free(key_out);
                }
            }
            free(key);
        } while (node);
        plist_mem_free(iter);
    }
    return 0;
}

static void unwrap_key_for_class(plist_t keybag_dict, uint32_t protection_class, unsigned char* persistent_key, int key_len, unsigned char* key_out, int* key_out_len)
{
    if (key_len != 0x28) {
        printf("invalid key length!\n");
    }

    plist_t classkeys = plist_dict_get_item(keybag_dict, "classkeys");
    char pclass[8];
    snprintf(pclass, 8, "%d", protection_class);
    plist_t classkey = plist_dict_get_item(classkeys, pclass);
    plist_t p_ck = plist_dict_get_item(classkey, "KEY");
    uint64_t ck_len = 0;
    unsigned char* ck = (unsigned char*)plist_get_data_ptr(p_ck, &ck_len);
    aes_unwrap(ck, persistent_key, key_len, key_out, key_out_len);
    hexdump(key_out, *key_out_len);
}

static void aes_decrypt_cbc_stream(FILE* fin, FILE* fout, unsigned char* key, int padding)
{
    const unsigned char iv[16] = { 0, };
    fseek(fin, 0, SEEK_SET);
    fseek(fout, 0, SEEK_SET);

    unsigned char buf[65536];

    while (!feof(fin)) {
        ssize_t r = fread(buf, 1, 65536, fin);
        ssize_t r_adj = r;
        if (r % 16) {
            r_adj = (r / 16) * 16 + 16;
            memset(buf + r, 0, r_adj - r);
        }
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        int len = 0;
        EVP_DecryptUpdate(ctx, buf, &len, buf, r_adj);
        EVP_DecryptFinal_ex(ctx, buf+len, &len);
        EVP_CIPHER_CTX_free(ctx);
        fwrite(buf, 1, r, fout);
    }
}

EXPORT libibackup_error_t libibackup_open_backup(const char* path, libibackup_client_t* client, const char* password) {
    assert(path);
    assert(client);

    if (libibackup_preflight_backup(path) == false) {
        return IBACKUP_E_INVALID_ARG;
    }

    struct libibackup_client_private* private_client = calloc(1, sizeof(struct libibackup_client_private));
    private_client->path = libibackup_ensure_directory(path);

    LIMD_log_message(LIMD_DEBUG, "backup", "Opening Info.plist\n");

    private_client->info = libibackup_load_plist(path, "Info.plist");

    LIMD_log_message(LIMD_DEBUG, "backup", "Opening Manifest.plist\n");

    private_client->manifest_info = libibackup_load_plist(path, "Manifest.plist");
    int is_encrypted = plist_dict_get_bool(private_client->manifest_info, "IsEncrypted");
    LIMD_log_message(LIMD_DEBUG, "backup", "Backup is encrypted: %s\n", (is_encrypted) ? "YES" : "NO");

    char* manifest_database_path = libibackup_combine_path(path, "Manifest.db");
    int db_result = -1;
    if (is_encrypted) {
        do {
            if (!password) {
                db_result = -2;
                break;
            }
            plist_t p_pver = plist_access_path(private_client->manifest_info, 2, "Lockdown", "ProductVersion");
            if (load_keys(private_client) != 0) {
                db_result = -3;
                break;
            }
            unsigned char key[32];
            derive_key_from_password(private_client, password, key, (numeric_device_version(plist_get_string_ptr(p_pver, NULL)) >= DEVICE_VERSION(10, 2, 0)));
            private_client->decryption_key = plist_new_data((char*)key, 32);
            plist_print(private_client->decryption_key);
            unlock_keys(private_client);
            if (numeric_device_version(plist_get_string_ptr(p_pver, NULL)) >= DEVICE_VERSION(10, 2, 0)) {
                plist_t p_manifest_key = plist_dict_get_item(private_client->manifest_info, "ManifestKey");
                uint64_t manifest_key_len = 0;
                unsigned char* manifest_key = (unsigned char*)plist_get_data_ptr(p_manifest_key, &manifest_key_len);
                uint32_t manifest_class = le32toh(*(uint32_t*)manifest_key);
                manifest_key += 4;
                manifest_key_len -= 4;
                unsigned char mani_key[32];
                int mani_key_len = 0;
                unwrap_key_for_class(private_client->keybag_dict, manifest_class, manifest_key, manifest_key_len, mani_key, &mani_key_len);
                FILE* fin = fopen(manifest_database_path, "rb");
                if (!fin) {
                    db_result = -4;
                    break;
                }
                char manifest_database_dec_path[PATH_MAX];
                snprintf(manifest_database_dec_path, PATH_MAX, "%s.dec", manifest_database_path);
                FILE* fout = fopen(manifest_database_dec_path, "wb");
                if (!fout) {
                    db_result = -4;
                    fclose(fin);
                    break;
                }
                aes_decrypt_cbc_stream(fin, fout, mani_key, 0);
                fclose(fin);
                fclose(fout);
                db_result = sqlite3_open_v2(manifest_database_dec_path, &private_client->manifest, SQLITE_OPEN_READWRITE, NULL);
            } else {
                db_result = sqlite3_open_v2(manifest_database_path, &private_client->manifest, SQLITE_OPEN_READWRITE, NULL);
            }
        } while (0);
    } else {
        db_result = sqlite3_open_v2(manifest_database_path, &private_client->manifest, SQLITE_OPEN_READWRITE, NULL);
    }
    LIMD_log_message(LIMD_DEBUG, "backup", "Opening Manifest DB result: %d\n", db_result);
    if (db_result != 0) {
        libibackup_close(private_client);
        return (db_result == -2) ? IBACKUP_E_MISSING_PASSWORD : IBACKUP_E_OPEN_ERROR;
    }

    *client = private_client;

    sqlite3_stmt *integrity_check;
    LIMD_log_message(LIMD_DEBUG, "backup", "Performing integrity check:\n");
    sqlite3_prepare_v3(private_client->manifest, integrity_check_query, strlen(integrity_check_query), SQLITE_PREPARE_NORMALIZE, &integrity_check, NULL);
    while (sqlite3_step(integrity_check) == SQLITE_ROW) {
        LIMD_log_message(LIMD_DEBUG, "backup", "%s\n", sqlite3_column_text(integrity_check, 0));
    }

    return IBACKUP_E_SUCCESS;
}

EXPORT libibackup_error_t libibackup_get_info(libibackup_client_t client, plist_t* info) {
    *info = plist_copy(client->info);

    return IBACKUP_E_SUCCESS;
}

EXPORT libibackup_error_t libibackup_list_domains(libibackup_client_t client, struct collection* domains) {
    assert(client);
    assert(domains);

    //uint32_t count = libibackup_manifest_query_count(client->manifest, domains_count_query, NULL);
    //collection_ensure_capacity(domains, count);
    collection_init(domains);

    sqlite3_stmt *query_domains;
    //int64_t index = 0;

    LIMD_log_message(LIMD_DEBUG, "backup", "Preparing Domain Statement\n");
    
    sqlite3_prepare_v3(client->manifest, domains_query, strlen(domains_query), SQLITE_PREPARE_NORMALIZE, &query_domains, NULL);

    while(sqlite3_step(query_domains) == SQLITE_ROW) {
        const char* domain_from_db = (const char*)sqlite3_column_text(query_domains, 0);

        LIMD_log_message(LIMD_DEBUG, "backup", "Found Domain: %s\n", domain_from_db);
        
        char* domain_str = (char*)malloc(strlen(domain_from_db) + 1);
        strcpy(domain_str, domain_from_db);
        collection_add(domains, domain_str);
        //index++;
    }

    sqlite3_finalize(query_domains);

    return IBACKUP_E_SUCCESS;
}

EXPORT libibackup_error_t libibackup_get_domain_metrics(libibackup_client_t client, const char* domain, libibackup_domain_metrics_t* metrics) {
    sqlite3_stmt *metrics_query;
    sqlite3_prepare_v3(client->manifest, domain_count_file_grouped_query, strlen(domain_count_file_grouped_query), SQLITE_PREPARE_NORMALIZE, &metrics_query, NULL);
    sqlite3_bind_text(metrics_query, 1, domain, strlen(domain), NULL);

    metrics->file_count = 0;
    metrics->directory_count = 0;
    metrics->symlink_count = 0;

    while (sqlite3_step(metrics_query) == SQLITE_ROW) {
        uint32_t count = sqlite3_column_int(metrics_query, 0);
        switch (sqlite3_column_int(metrics_query, 1)) {
            case IBACKUP_FLAG_FILE:
                metrics->file_count = count;
                break;
            case IBACKUP_FLAG_DIRECTORY:
                metrics->directory_count = count;
                break;
            case IBACKUP_FLAG_SYMBOLIC_LINK:
                metrics->symlink_count = count;
                break;
        }
    }

    return IBACKUP_E_SUCCESS;
}

EXPORT libibackup_error_t libibackup_get_metadata_by_id(libibackup_client_t client, const char* file_id, libibackup_file_metadata_t* metadata) {
    memset(metadata, 0, sizeof(libibackup_file_metadata_t));

    plist_t raw_metadata;
    libibackup_get_raw_metadata_by_id(client, file_id, &raw_metadata);

    plist_t objects = plist_dict_get_item(raw_metadata, "$objects");
    plist_t mb_file = plist_array_get_item(objects, 1);
    plist_t size_item = plist_dict_get_item(mb_file, "Size");
    plist_t target_item = plist_dict_get_item(mb_file, "Target");
    plist_get_uint_val(size_item, &metadata->size);

    if (target_item != NULL) {
        uint64_t index;
        plist_get_uid_val(target_item, &index);
        plist_t target_string_value = plist_array_get_item(objects, index);
        plist_get_string_val(target_string_value, &metadata->target);

        plist_free(target_string_value);
        plist_free(target_item);
    }

    plist_free(size_item);
    plist_free(mb_file);
    plist_free(objects);

    plist_free(raw_metadata);

    return IBACKUP_E_SUCCESS;
}

EXPORT libibackup_error_t libibackup_list_files_for_domain(libibackup_client_t client, const char* domain, /* of libibackup_file_entry_t */ struct collection* files) {
    assert(files);

    uint32_t count; //, index;

    count = libibackup_manifest_query_count(client->manifest, domain_count_file_query, domain);

    LIMD_log_message(LIMD_DEBUG, "backup", "Files Count for Domain %s is %d\n", domain, count);

    //collection_ensure_capacity(files, count);
    collection_init(files);

    sqlite3_stmt *query_files;

    int result = sqlite3_prepare_v3(client->manifest, domain_file_query, strlen(domain_file_query), SQLITE_PREPARE_NORMALIZE, &query_files, NULL);

    sqlite3_bind_text(query_files, 1, domain, strlen(domain), NULL);

    LIMD_log_message(LIMD_DEBUG, "backup", "File query prepare result %i\n", result);

    //index = 0;
    while(sqlite3_step(query_files) == SQLITE_ROW) {
        libibackup_file_entry_t *entry = malloc(sizeof(libibackup_file_entry_t));
        //files->list[index] = entry;

        char* relative_path = (char*)sqlite3_column_text(query_files, 2);
        char* file_id = (char*)sqlite3_column_text(query_files, 0);

        entry->relative_path = malloc(strlen(relative_path) + 1);
        entry->domain = malloc(strlen(domain) + 1);
        entry->file_id = malloc(strlen(file_id) + 1);
        entry->type = sqlite3_column_int(query_files, 3);
        strcpy(entry->file_id, file_id);
        strcpy(entry->relative_path, relative_path);
        strcpy(entry->domain, domain);

        collection_add(files, entry);
        //index++;
    }

    sqlite3_finalize(query_files);

    return IBACKUP_E_SUCCESS;
}

EXPORT libibackup_error_t libibackup_close(libibackup_client_t client) {
    if (client != NULL) {
        free(client->path);
        plist_free(client->info);
        plist_free(client->manifest_info);
        if (client->manifest) {
            sqlite3_close_v2(client->manifest);
        }
        plist_free(client->keybag_dict);
        free(client);
    }

    return IBACKUP_E_SUCCESS;
}

EXPORT void libibackup_free(void* object) {
    free(object);
}
