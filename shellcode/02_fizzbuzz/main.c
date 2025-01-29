#include <stdio.h>
#include <stdint.h>

extern int do_fizzbuzz(uint32_t* b);

int main(){
	uint32_t a[2048];
	int res;
	
	for (int i = 0; i < 2048; i++)
	{
		a[i] = i+1;
	}
	res = do_fizzbuzz(a);
	for (int i = 0; i < 16; i++)
	{
		printf("%x\n", a[i]);
	}
	printf("res: %d\n", res);
	return res;
}