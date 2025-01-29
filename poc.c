#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <curl/curl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#include <limits.h>

#define DATABASE_FILE "database.txt"
#ifndef DT_DIR
    #define DT_DIR 4
#endif

#ifndef PATH_MAX
    #define PATH_MAX 4096
#endif

// Function prototypes
void scan_directory(const char *dir_path, int depth);
void scan_file(const char *file_path);
int is_archive(const char *file_name);
void extract_and_scan(const char *archive_path, int depth);
int is_sha_in_database(const char *sha);
void add_sha_to_database(const char *sha);
void calculate_sha256(const char *file_path, char *output_buffer);
void send_api_request(const char *sha);
int is_regular_file(const char *path);
void log_message(const char *message);
void log_scan_stats(int scanned_files, int scanned_folders, int total_files, int total_dirs, double elapsed_time);

int viruses_detected = 0; // Global variable to track the number of viruses detected
int scanned_files = 0;
int scanned_folders = 0;
int total_files = 0;  // To hold total number of files
int total_dirs = 0;   // To hold total number of directories
time_t start_time;

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path_to_scan>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Start timing the scan
    start_time = time(NULL);
    log_message("Starting directory scan...");

    // Initialize global counters
    total_files = 0;
    total_dirs = 0;

    // First pass: Calculate total files and directories
    scan_directory(argv[1], 0);

    // Reset scanned counters before the actual scan
    scanned_files = 0;
    scanned_folders = 0;

    // Second pass: Scan the directory
    scan_directory(argv[1], 0);

    // Calculate elapsed time
    double elapsed_time = difftime(time(NULL), start_time);
    
    // Log final stats to output.txt
    log_scan_stats(scanned_files, scanned_folders, total_files, total_dirs, elapsed_time);

    log_message("Directory scan completed.");
    return EXIT_SUCCESS;
}

size_t write_callback(void *contents, size_t size, size_t nmemb, char *output) {
    size_t total_size = size * nmemb;
    strncat(output, contents, total_size);
    return total_size;
}

void log_message(const char *message) {
    FILE *log_file = fopen("scan_log.txt", "a"); // Open log file for appending
    if (log_file) {
        fprintf(log_file, "%s\n", message); // Write message to log file
        fclose(log_file); // Close the log file
    } else {
        perror("Unable to open log file");
    }

    // Also print to the console for immediate feedback
    printf("%s\n", message);
}

void scan_directory(const char *dir_path, int depth) {
    if (depth > PATH_MAX) return; // Limit recursion depth

    struct stat path_stat;
    if (stat(dir_path, &path_stat) == -1) {
        perror("stat");
        log_message("Error: Unable to stat the directory.");
        return;
    }

    if (!S_ISDIR(path_stat.st_mode)) {
        fprintf(stderr, "%s is not a directory\n", dir_path);
        log_message("Error: Not a directory.");
        return;
    }

    DIR *dir = opendir(dir_path);
    if (!dir) {
        perror("opendir");
        log_message("Error: Unable to open directory.");
        return;
    }

    total_dirs++; // Increment total directory count
    scanned_folders++; // Increment scanned folder count
    log_message("Scanning directory...");

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        char full_path[PATH_MAX];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

        if (stat(full_path, &path_stat) == -1) {
            perror("stat");
            continue;
        }

        printf("Processing: %s\n", full_path);

        if (S_ISREG(path_stat.st_mode)) { // If it's a regular file
            total_files++;  // Increment total file count
            scanned_files++; // Increment scanned file count
            printf("Scanning file: %s\n", full_path);
            scan_file(full_path);  // Scan the file
        } else if (S_ISDIR(path_stat.st_mode)) { // If it's a directory
            total_dirs++;  // Increment total directory count
            printf("Entering directory: %s\n", full_path);
            scan_directory(full_path, depth + 1); // Recursively scan subdirectories
        }
    }

    closedir(dir);
}

void scan_file(const char *file_path) {
    // Debugging: Ensure file path is passed correctly
    printf("Scanning file at path: %s\n", file_path);

    char sha256[65];
    calculate_sha256(file_path, sha256);

    if (is_sha_in_database(sha256)) {
        printf("File already in database: %s\n", file_path);
        log_message("File already in database.");
        return;
    }

    send_api_request(sha256);

    int is_virus = rand() % 2;  // Simulate a virus detection
    if (is_virus) {
        printf("Virus detected: %s (SHA: %s)\n", file_path, sha256);
        log_message("Virus detected and logged.");
        add_sha_to_database(sha256);
        viruses_detected++; // Increment virus count
    }

    scanned_files++; // Increment file count
}


int is_archive(const char *file_name) {
    const char *ext = strrchr(file_name, '.');
    return ext && (strcmp(ext, ".zip") == 0 || strcmp(ext, ".tar") == 0 || strcmp(ext, ".gz") == 0);
}

void extract_and_scan(const char *archive_path, int depth) {
    printf("Extracting and scanning archive: %s\n", archive_path);
    log_message("Extracting and scanning archive...");
}

void calculate_sha256(const char *file_path, char *output_buffer) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("fopen");
        log_message("Error opening file for SHA256 calculation.");
        return;
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    unsigned char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        SHA256_Update(&sha256, buffer, bytes_read);
    }

    fclose(file);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output_buffer + (i * 2), "%02x", hash[i]);
    }
    output_buffer[64] = '\0';
}

void send_api_request(const char *sha) {
    CURL *curl = curl_easy_init();
    if (!curl) return;

    char url[256];
    snprintf(url, sizeof(url), "https://virus.exchange/api/samples/%s", sha);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Authorization: Bearer 9wIEyobWBF0l0pRpT7fHIA6tRdxsY+1U");

    char response[4096] = ""; // Buffer to hold the response body
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "CURL error: %s\n", curl_easy_strerror(res));
        log_message("Error sending API request.");
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return;
    }

    // Check if the response contains "Not Found" error
    if (strstr(response, "\"errors\":{\"detail\":\"Not Found\"}")) {
        printf("No virus detected: %s\n", sha);
        log_message("No virus detected.");
    } else {
        printf("Virus detected: %s\n", sha);
        log_message("Virus detected and logged.");
        // Add to database or take other actions if needed
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}
int is_sha_in_database(const char *sha) {
    FILE *db = fopen(DATABASE_FILE, "r");
    if (!db) return 0;

    char line[65];
    while (fgets(line, sizeof(line), db)) {
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, sha) == 0) {
            fclose(db);
            log_message("SHA found in database.");
            return 1;
        }
    }

    fclose(db);
    log_message("SHA not found in database.");
    return 0;
}

void add_sha_to_database(const char *sha) {
    FILE *db = fopen(DATABASE_FILE, "a");
    if (!db) {
        perror("fopen");
        log_message("Error opening database for writing.");
        return;
    }

    fprintf(db, "%s\n", sha);
    fclose(db);
    log_message("SHA added to database.");
}

void log_scan_stats(int scanned_files, int scanned_folders, int total_files, int total_dirs, double elapsed_time) {
    FILE *output_file = fopen("output.txt", "w");
    if (!output_file) {
        perror("Error opening output file");
        return;
    }

    fprintf(output_file, "Scan Statistics:\n");
    fprintf(output_file, "Total files found: %d\n", total_files);
    fprintf(output_file, "Total directories found: %d\n", total_dirs);
    fprintf(output_file, "Total files scanned: %d\n", scanned_files);
    fprintf(output_file, "Total folders scanned: %d\n", scanned_folders);
    fprintf(output_file, "Elapsed time: %.2f seconds\n", elapsed_time);
    fprintf(output_file, "Total viruses detected: %d\n", viruses_detected); // Log viruses detected

    fclose(output_file);
}
