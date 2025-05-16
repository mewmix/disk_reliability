#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <signal.h>

#define DEFAULT_BLOCK_SIZE 4096      // 4 KiB
#define DEFAULT_TEST_THREADS 4       // concurrency
#define TEST_FILE_NAME "disk_test_file.bin"
#define SAFETY_FACTOR 0.10           // 10% margin for free space

volatile sig_atomic_t stop_requested = 0;  // For Ctrl+C handling

typedef struct {
    int thread_id;
    int fd;
    off_t start_offset;
    off_t end_offset;
    size_t block_size;
    unsigned char *pattern;
} ThreadArgs;

void handle_sigint(int sig) {
    stop_requested = 1;
    fprintf(stderr, "Received Ctrl+C. Stopping...\n");
}

void generate_pattern(unsigned char *buffer, size_t size, off_t offset) {
    for (size_t i = 0; i < size; i++) {
        buffer[i] = (offset + i) % 256;  // Simple pattern
    }
}

void *read_write_verify(void *args) {
    ThreadArgs *thread_args = (ThreadArgs *)args;
    int fd = thread_args->fd;
    off_t start_offset = thread_args->start_offset;
    off_t end_offset = thread_args->end_offset;
    size_t block_size = thread_args->block_size;
    unsigned char *pattern = thread_args->pattern;

    unsigned char *read_buffer = malloc(block_size);
    unsigned char *write_buffer = malloc(block_size);

    if (!read_buffer || !write_buffer) {
        perror("Memory allocation failed");
        pthread_exit((void *)1);
    }

    for (off_t offset = start_offset; offset < end_offset; offset += block_size) {
        if (stop_requested) break;

        // Generate write pattern
        generate_pattern(write_buffer, block_size, offset);

        // Write the block
        if (pwrite(fd, write_buffer, block_size, offset) != block_size) {
            perror("Write error");
            break;
        }

        // Read the block
        if (pread(fd, read_buffer, block_size, offset) != block_size) {
            perror("Read error");
            break;
        }

        // Verify the block
        if (memcmp(write_buffer, read_buffer, block_size) != 0) {
            fprintf(stderr, "[Thread %d] Mismatch at offset %ld\n", thread_args->thread_id, offset);
        }
    }

    free(read_buffer);
    free(write_buffer);
    pthread_exit(NULL);
}

off_t get_free_space(const char *path) {
    struct statvfs stat;
    if (statvfs(path, &stat) != 0) {
        perror("statvfs failed");
        return -1;
    }
    return stat.f_bavail * stat.f_frsize;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, handle_sigint);

    size_t block_size = DEFAULT_BLOCK_SIZE;
    int num_threads = DEFAULT_TEST_THREADS;

    // Determine free space
    off_t free_space = get_free_space(".");
    if (free_space < 0) {
        fprintf(stderr, "Failed to determine free space.\n");
        return 1;
    }

    // Calculate test file size with safety factor
    size_t total_bytes = (size_t)(free_space * (1.0 - SAFETY_FACTOR));
    size_t total_blocks = total_bytes / block_size;

    // Preallocate test file
    int fd = open(TEST_FILE_NAME, O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        perror("Failed to open test file");
        return 1;
    }

    if (ftruncate(fd, total_bytes) != 0) {
        perror("Failed to preallocate file");
        close(fd);
        return 1;
    }

    // Create threads
    pthread_t threads[num_threads];
    ThreadArgs thread_args[num_threads];
    size_t blocks_per_thread = total_blocks / num_threads;

    for (int i = 0; i < num_threads; i++) {
        thread_args[i].thread_id = i;
        thread_args[i].fd = fd;
        thread_args[i].start_offset = i * blocks_per_thread * block_size;
        thread_args[i].end_offset = (i == num_threads - 1)
                                        ? total_blocks * block_size
                                        : thread_args[i].start_offset + blocks_per_thread * block_size;
        thread_args[i].block_size = block_size;
        thread_args[i].pattern = NULL;

        if (pthread_create(&threads[i], NULL, read_write_verify, &thread_args[i]) != 0) {
            perror("Failed to create thread");
            close(fd);
            return 1;
        }
    }

    // Wait for threads to complete
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    close(fd);
    printf("Test completed.\n");
    return 0;
}
