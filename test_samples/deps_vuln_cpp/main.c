#include <stdio.h>
#include <curl/curl.h>

/*
 * Beginner-friendly C demonstration program using libcurl.
 * Demonstrates initialization, HTTP request execution, error handling, and cleanup.
 */
int main(void) {
    CURL *curl;
    CURLcode res;

    // 1. Initialize curl session
    curl = curl_easy_init();
    if (curl) {
        // 2. Configure target URL
        curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

        // 3. Perform the HTTP request
        res = curl_easy_perform(curl);

        // 4. Check for errors
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            printf("\nRequest completed successfully.\n");
        }

        // 5. Clean up curl resources
        curl_easy_cleanup(curl);
    }

    return 0;
}
