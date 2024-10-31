#include <stdio.h>
#include <stdint.h>

// Set a few times higher than L2 size.
#define FLUSH_SIZE 4 * 1024 * 4096
unsigned char mem[FLUSH_SIZE];

void flush_cache() {
  int i;

  for (i = 0; i < FLUSH_SIZE; i++) {
    mem[i] = 0;
  }
}

// You might need to configure these.
#define SCORE_MEASURES 8
#define PREFETCH_INTENSITY 50
#define ADDR 0xffffffffcafebabe


uint64_t measure_time() {
  unsigned int lo1, hi1;
  unsigned int lo2, hi2;
  uint64_t time;
  flush_cache();

  __asm__ __volatile__ ("rdtsc" : "=a"(lo1), "=d"(hi1));
  for (int i = 0; i < PREFETCH_INTENSITY; i++) {
    __asm__ __volatile__ ("prefetcht2 %0": :"m"(*(unsigned char*)ADDR));
  }
  __asm__ __volatile__ ("rdtsc" : "=a"(lo2), "=d"(hi2));

  time = (hi2 - hi1) * 0xffffffff - lo1 + lo2;
  return time;
}


unsigned int measure_score() {
  int i;
  unsigned int summ = 0;

  for (i = 0; i < SCORE_MEASURES; i++) {
    summ += measure_time();
  }

  return summ;
}

int main() {
  int score;

  score = measure_score();
  printf("%f\n", (float)score);

  return 0;
}