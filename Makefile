svi2-dec: svi2-dec.c
	gcc -O0 -g -Werror -Wall -Wextra -pedantic -std=c99 -fsanitize=address -o svi2-dec svi2-dec.c
