#include <stdio.h>
#include <unistd.h>

int main() {
    printf("Payload executed from memory!\n");

    for (int i = 5; i > 0; i--) {
        printf("Running... %d\n", i);
        sleep(1);
    }

    printf("Exiting payload.\n");
    return 0;
}
