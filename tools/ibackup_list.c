#include <libibackup/libibackup.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <plist/plist.h>

#ifdef __cplusplus
extern "C" {
#endif


void list_domains(libibackup_client_t client) {
    printf("Listing Domains\n");
    char **domain_list;
    libibackup_list_domains(client, &domain_list);

    int64_t index = 0;
    while (domain_list[index] != NULL) {
        printf("Domain: %s\n", domain_list[index]);

        free(domain_list[index]);
        index++;
    }

    free(domain_list);
}

void list_files(libibackup_client_t client, char* domain) {
    printf("Listing files for domain %s\n", domain);
    libibackup_file_entry_t **file_list;

    libibackup_list_files_for_domain(client, domain, &file_list);

    int64_t index = 0;
    while (file_list[index] != NULL) {
        printf("%s: %s\n", file_list[index]->file_id, file_list[index]->relative_path);
        index++;
    }

    free(file_list);
}

void get_file_metadata(libibackup_client_t client, char* file_id) {
    plist_t metadata;
    char* xml;
    uint32_t length;
    libibackup_get_file_metadata_by_id(client, file_id, &metadata);

    plist_to_xml(metadata, &xml, &length);

    printf("Metadata\n%s\n", xml);
}

void get_file(libibackup_client_t client, char* file_id) {
    char* file_path;
    struct stat path_stat;

    libibackup_get_file_by_id(client, file_id, &file_path);
    stat(file_path, &path_stat);

    FILE* file = fopen(file_path, "r");
    if (file == NULL) {
        printf("Unable to read file\n");
        return;
    }
    void* data = malloc(path_stat.st_size);
    printf("Read file with size %lld\n", path_stat.st_size);

    fread(data, path_stat.st_size, 1, file);
    fclose(file);

    printf("Read Data Complete\n");

    write(STDOUT_FILENO, data, path_stat.st_size);
}

int main(int argc, char **argv) {
    libibackup_set_debug(true);
    if (argc < 3) {
        printf("Invalid Arguments\n");
        return -1;
    }

    libibackup_client_t client;

    libibackup_open_backup(argv[2], &client);

    printf("Backup Opened\n");


    if (strcmp(argv[1], "list_domains") == 0) {
        list_domains(client);
    }
    if (strcmp(argv[1], "list_files") == 0) {
        list_files(client, argv[3]);
    }
    if (strcmp(argv[1], "get_file_metadata") == 0) {
        get_file_metadata(client, argv[3]);
    }
    if (strcmp(argv[1], "get_file") == 0) {
        get_file(client, argv[3]);
    }

    libibackup_close(client);

    return 0;
}

#ifdef __cplusplus
}
#endif