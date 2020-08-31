#include <unistd.h>

void toto()
{
        write(1, "hello\n", 6);
}

int main()
{
        toto();
        toto();
        return (1);
}
