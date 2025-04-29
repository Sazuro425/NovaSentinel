#include <stdio.h>
#include <sys/sysinfo.h>
#include <stdlib.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <dirent.h>
#include <ctype.h>
#include <string.h>


void infosmachine() {  
    struct sysinfo machine;

    // Get system information
    if (sysinfo(&machine) != 0) {
        perror("sysinfo");
        return;
    }

    // Print memory information
    printf("Free RAM: %lu bytes\n", machine.freeram);
    printf("Total RAM: %lu bytes\n", machine.totalram);
    printf("Uptime: %ld seconds\n", machine.uptime);
    printf("Number of Processes: %u\n", machine.procs);
    printf("Load averages (1min, 5min, 15min): %.2f, %.2f, %.2f\n", 
       machine.loads[0] / 65536.0, 
       machine.loads[1] / 65536.0, 
       machine.loads[2] / 65536.0);
}

void get_disk_space(const char *path) {
    struct statvfs stat;

    if (statvfs(path, &stat) != 0) {
        perror("Erreur lors de la récupération des infos disque");
        return;
    }

    unsigned long total = stat.f_blocks * stat.f_frsize;  // Espace total
    unsigned long free = stat.f_bfree * stat.f_frsize;    // Espace libre total

    printf("Espace total : %lu bytes\n",total);
    printf("Espace libre : %lu bytes\n", free);
}

#define PROC_DIR "/proc"
#define MAX_PATH 1024

// Vérifie si une chaîne est un nombre (vérifie chaque caractère)
int is_number(const char *str) {
    for (size_t i = 0; str[i] != '\0'; i++) {
        if (!isdigit((unsigned char)str[i])) {
            return 0;
        }
    }
    return 1;
}

void get_pid() {
    DIR *dir = opendir(PROC_DIR);
    if (!dir) {
        perror("Erreur : impossible d'ouvrir /proc");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Vérifie si le nom du dossier est un nombre (correspond à un PID)
        if (is_number(entry->d_name)) {
            char path[MAX_PATH];
            snprintf(path, sizeof(path), PROC_DIR "/%s/cmdline", entry->d_name);

            FILE *fp = fopen(path, "r");
            if (fp) {
                ch;ar cmdline[MAX_PATH] = {0};
                size_t bytesRead = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
                fclose(fp);

                if (bytesRead > 0) {
                    cmdline[bytesRead] = '\0';  // Assurer la terminaison de la chaîne
                } else {
                    snprintf(cmdline, sizeof(cmdline), "[%s]", entry->d_name);
                }

                //printf("PID: %s | Commande: %s\n", entry->d_name, cmdline);
            }
        }
    }

    closedir(dir);
}
    
int main() {
    infosmachine();
    get_disk_space("/");
    get_pid();
    return 0;
}