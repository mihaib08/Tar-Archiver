// Mihai-Eugen Barbu
// 315CA

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define LMAX 512
#define files "files.txt"
#define users "usermap.txt"

union record {
    char chrptr[512];
    struct header {
        char name[100];
        char mode[8];
        char uid[8];
        char gid[8];
        char size[12];
        char mtime[12];
        char chksum[8];
        char typeflag;
        char linkname[100];
        char magic[8];
        char uname[32];
        char gname[32];
        char devmajor[8];
        char devminor[8];
    } header;
};

int check_create(char *cmd) {
    char sep[] = " ";
    cmd = strtok(NULL, sep); // Name_arch
    // printf("%s\n", cmd);
    if (cmd) {
        cmd = strtok(NULL, sep); // Name_dir
        if (cmd) {
            cmd = strtok(NULL, sep);
            FILE *f = fopen(files, "rb");
            if (f == NULL) {
                return -1;
            } else {
                fclose(f);
                return 1;
            }
        } else {
            return 0;
        }
    } else {
        return 0;
    }
}

int check_list(char *cmd) {
    char sep[] = " ";
    cmd = strtok(NULL, sep); // Name_arch
    if (cmd) {
        cmd = strtok(NULL, sep);
        if (!cmd) {
            return 1;
        } else {
            return 0;
        }
    } else {
        return 0;
    }
}

int check_extract(char *cmd) {
    char sep[] = " ";
    cmd = strtok(NULL, sep); // Name_file
    if (cmd) {
        cmd = strtok(NULL, sep); // Name_arch
        if (cmd) {
            cmd = strtok(NULL, sep);
            if (!cmd) {
                return 1;
            } else {
                return 0;
            }
        } else {
            return 0;
        }
    } else {
        return 0;
    }
}

void find_id(char *user, int *u_id, int *g_id) {
    char s[LMAX], *p;
    strcpy(s, user);
    FILE *u = fopen(users, "rb");
    char info[LMAX];
    while (fgets(info, LMAX, u)) {
        p = strtok(info, ":");
        if (strcmp(s, p) == 0) {
            p = strtok(NULL, ":");
            p = strtok(NULL, ":"); // UID
            *u_id = atoi(p);
            p = strtok(NULL, ":"); // GID
            *g_id = atoi(p);
        }
    }
    fclose(u);
}

void check_per(char *per, char *rez) {
    int i;
    char s[] = "xrw";
    int p[] = {1, 4, 2};
    for (i = 1; i <= 3; ++i) {
        if (per[i] == s[i%3]) {
            rez[4] += p[i%3];
        }
    }
    for (i = 4; i <= 6; ++i) {
        if (per[i] == s[i%3]) {
            rez[5] += p[i%3];
        }
    }
    for (i = 7; i <= 9; ++i) {
        if (per[i] == s[i%3]) {
            rez[6] += p[i%3];
        }
    }
}

time_t check_time(char *days, char *time) {
    char sep[] = "-:.";
    char *p;
    struct tm Time = {0};
    time_t sec;
    p = strtok(days, sep);
    Time.tm_year = atoi(p) - 1900;
    p = strtok(NULL, sep);
    Time.tm_mon = atoi(p) - 1;
    p = strtok(NULL, sep);
    Time.tm_mday = atoi(p);

    p = strtok(time, sep);
    Time.tm_hour = atoi(p);
    p = strtok(NULL, sep);
    Time.tm_min = atoi(p);
    p = strtok(NULL, sep);
    Time.tm_sec = atoi(p);
    sec = mktime(&Time);
    /* ptm = gmtime(&sec);
    sec = mktime(ptm); */
    return sec;
}

int deci(int oct) {
    int nr = oct, res = 0, p = 1;
    while (nr) {
        res += (nr % 10) * p;
        nr /= 10;
        p *= 8;
    }
    return res;
}

union record fill_union(char *info) {
    int i;
    char *p, sep[] = " ";
    char per[LMAX], u_name[LMAX], g_name[LMAX], size[LMAX], name[LMAX];
    char days[LMAX], time[LMAX]; // Time_var
    char data[LMAX];
    union record rec;
    p = strtok(info, sep);
    strcpy(per, p);
    p = strtok(NULL, sep);
    p = strtok(NULL, sep); // User_name
    strcpy(u_name, p);
    p = strtok(NULL, sep); // Group_name
    strcpy(g_name, p);
    p = strtok(NULL, sep); // Size
    strcpy(size, p);
    p = strtok(NULL, sep); // Days
    strcpy(days, p);
    // printf("%s\n", days);
    p = strtok(NULL, sep); // Time
    strcpy(time, p);
    // printf("%s\n", time);
    p = strtok(NULL, sep); // Timezone
    p = strtok(NULL, sep); // Filename
    strcpy(name, p);
    memset(rec.chrptr, '\0', LMAX);

    // Fill in the *union*

    sprintf(rec.header.name, "%s", name);
    sprintf(rec.header.mode, "0000000");
    check_per(per, rec.header.mode);
    int u_id, g_id;
    find_id(u_name, &u_id, &g_id);
    sprintf(rec.header.uid, "%07o", u_id);
    sprintf(rec.header.gid, "%07o", g_id);
    int sz = atoi(size);
    sprintf(rec.header.size, "%011o", sz);

    // Check_time

    time_t sec;
    sec = check_time(days, time);
    sprintf(rec.header.mtime, "%011lo", sec);

    rec.header.typeflag = '\0';
    sprintf(rec.header.linkname, "%s", name);
    sprintf(rec.header.magic, "GNUtar ");
    rec.header.magic[7] = '\0';

    sprintf(rec.header.uname, "%s", u_name);
    sprintf(rec.header.gname, "%s", g_name);
    rec.header.devmajor[0] = '\0';
    rec.header.devminor[0] = '\0';

    unsigned int sum = 0;

    for (i = 0; i < 512; ++i) {
        sum += (unsigned char) rec.chrptr[i];
    }

    // Blank spaces (ascii = 32) for chksum[8] --> 8*32 = 256
    sum += 256;
    sprintf(rec.header.chksum, "%06o", sum);
    rec.header.chksum[7] = ' ';
    return rec;
}

void res_create(char *cmd) {
    int i, sz;
    char *p, sep[] = " ";
    char name_arch[LMAX], name_dir[LMAX];
    char data[LMAX];
    union record rec;
    p = strtok(cmd, sep);
    p = strtok(NULL, sep); // Name_arch
    strcpy(name_arch, p);

    p = strtok(NULL, sep); // Name_dir
    strcpy(name_dir, p);

    printf("> Done!\n");

    FILE *f = fopen(files, "rb");
    char info[LMAX];
    fgets(info, LMAX, f);
    info[strlen(info) - 1] = '\0';
    rec = fill_union(info);

    FILE *arch = fopen(name_arch, "wb");
    strcpy(data, name_dir);
    strcat(data, rec.header.name);

    FILE *g = fopen(data, "rb");
    fwrite(&rec, sizeof(union record), 1, arch);
    char c_0, c;
    c_0 = '\0';
    sz = atoi(rec.header.size);
    sz = deci(sz);

    if (g != NULL) {
        while (fread(&c, sizeof(char), 1, g)) {
            fwrite(&c, sizeof(char), 1, arch);
        }
        if (sz % 512) {
            int nr = sz / 512;
            nr = (nr + 1) * 512 - sz;
            for (i = 0; i < nr; ++i) {
                fwrite(&c_0, sizeof(char), 1, arch);
            }
        }
    }

    fclose(g);

    while (fgets(info, LMAX, f)) {
        info[strlen(info) - 1] = '\0';
        rec = fill_union(info);
        strcpy(data, name_dir);
        strcat(data, rec.header.name);
        g = fopen(data, "rb");
        fwrite(&rec, sizeof(union record), 1, arch);
        char c_0, c;
        c_0 = '\0';
        if (g != NULL) {
            while (fread(&c, sizeof(char), 1, g)) {
                fwrite(&c, sizeof(char), 1, arch);
            }

            sz = atoi(rec.header.size);
            sz = deci(sz);

            if (sz % 512) {
                int nr = sz / 512;
                nr = (nr + 1) * 512 - sz;
                for (i = 0; i < nr; ++i) {
                    fwrite(&c_0, sizeof(char), 1, arch);
                }
            }
        }

        fclose(g);
    }

    for (i = 0; i < LMAX; ++i) {
        fwrite(&c_0, sizeof(char), 1, arch);
    }

    fclose(f);
    fclose(arch);
}

int closest_mul(int nr) {  // The lowest multiple of 512 bigger than nr
    if (nr % 512 == 0) {
        return nr;
    } else {
        int a = nr / 512;
        a = (a + 1) * 512;
        return a;
    }
}

void res_list(char *name_arch) {
    FILE *arch = fopen(name_arch, "rb");
    int sz;
    if (arch == NULL) {
        printf("> File not found!\n");
        return;
    } else {
        union record rec;

        fread(&rec, sizeof(union record), 1, arch);

        while (rec.header.name[0] != '\0') {
            printf("> %s\n", rec.header.name);
            sz = atoi(rec.header.size);
            sz = deci(sz);
            // printf("%d\n", sz);
            sz = closest_mul(sz);
            // printf("%d\n", sz);
            fseek(arch, sz, SEEK_CUR);
            fread(&rec, sizeof(union record), 1, arch);
        }
    }

    fclose(arch);
}

void res_extract(char *name_arch, char *name_file) {
    FILE *arch = fopen(name_arch, "rb");
    int sz;
    if (arch == NULL) {
        printf("> File not found!\n");
        return;
    } else {
        union record rec;
        fread(&rec, sizeof(union record), 1, arch);
        while (rec.header.name[0] != '\0') {
            // printf("> %s\n", rec.header.name);
            if (strcmp(rec.header.name, name_file) == 0) {
                printf("> File extracted!\n");
                char s[LMAX];
                strcpy(s, "extracted_");
                strcat(s, name_file);
                FILE *g = fopen(s, "wb");
                char c;
                int i;
                sz = atoi(rec.header.size);
                sz = deci(sz);
                for (i = 0; i < sz; ++i) {
                    fread(&c, sizeof(char), 1, arch);
                    fwrite(&c, sizeof(char), 1, g);
                }
                fclose(g);
                fclose(arch);
                return;
            }
            sz = atoi(rec.header.size);
            sz = deci(sz);
            // printf("%d\n", sz);
            sz = closest_mul(sz);
            // printf("%d\n", sz);
            fseek(arch, sz, SEEK_CUR);
            fread(&rec, sizeof(union record), 1, arch);
        }
    }
    printf("> File not found!\n");
    fclose(arch);
}

int main() {
    int cr;
    char cmd[LMAX], cp_cmd[LMAX], *p;
    char sep[] = " ";
    fgets(cmd, LMAX, stdin);
    cmd[strlen(cmd) - 1] = '\0';
    while (strcmp(cmd, "exit")) {
        strcpy(cp_cmd, cmd);
        p = strtok(cp_cmd, sep);

        if (strcmp(p, "create") == 0) {
            cr = check_create(cp_cmd);
            if (cr == 0) {
                printf("> Wrong command!\n");
            } else if (cr == -1) {
                printf("> Failed!\n");
            } else {
                res_create(cmd);
            }
        } else if (strcmp(p, "list") == 0) {
            if (check_list(cp_cmd)) {
                p = strtok(cmd, sep);
                p = strtok(NULL, sep);
                res_list(p);
            } else {
                printf("> Wrong command!\n");
            }
        } else if (strcmp(p, "extract") == 0) {
            if (check_extract(cp_cmd)) {
                char name_arch[LMAX], name_file[LMAX];

                p = strtok(cmd, sep);
                p = strtok(NULL, sep);
                strcpy(name_file, p);

                p = strtok(NULL, sep);
                strcpy(name_arch, p);

                res_extract(name_arch, name_file);
            } else {
                printf("> Wrong command!\n");
            }
        } else {
            printf("> Wrong command!\n");
        }

        fgets(cmd, LMAX, stdin);
        cmd[strlen(cmd) - 1] = '\0';
    }

    return 0;
}
